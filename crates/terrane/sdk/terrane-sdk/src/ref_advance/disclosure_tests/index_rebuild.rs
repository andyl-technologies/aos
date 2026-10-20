//! Composes immutable rebuild/completion with genuine signed producer admission.
//!
//! Query results remain candidates; separate native reads prove current target
//! and producer access. Exhaustive construction work is not incremental work.

use super::witness_support::*;
use super::*;
use crate::guard::{
    AuthoringNamespaceProfile, RecordedNamespaceProfile, RecordedNamespaceProfiles,
};
use crate::ref_advance::{CommitRequest, DisclosureCommitRequest, DisclosureCommitSelection};
use crate::repository::local_authority::{LocalAuthority, LocalAuthorityParameters};
use crate::repository::{MetadataValidator, Repository};
use crate::store::{InvalidReason, LocalFs, RefStore, StoreErrorKind};
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Deref;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;
use terrane_format::cbor;
use terrane_format::derived::{AttrRecord, AttributeValue, PlaintextHashes};
use terrane_format::identity::Digest;
use terrane_format::indexing::{
    IndexEvaluationRecipe, carrier::SemanticContext, completion, evaluation, incremental,
    maintenance,
};
use terrane_format::properties::semantics::associations::RecordedAssociation;
use terrane_format::tree_format::Attribute;

const ATTRIBUTE: &str = "hash.sha256";

type NativeIndexRepository =
    Repository<FileBucket<TokioLocalFs, TokioClock, MetadataValidator>, TokioClock, TokioLocalFs>;

/// Retains the independently installed profile through genuine native reopen.
struct RebuildFixture {
    repository: NativeIndexRepository,
    authoring: AuthoringNamespaceProfile,
}

impl Deref for RebuildFixture {
    type Target = Coordinator<
        FileBucket<TokioLocalFs, TokioClock, MetadataValidator>,
        TokioClock,
        TokioLocalFs,
    >;

    fn deref(&self) -> &Self::Target {
        self.repository.coordinator()
    }
}

impl RebuildFixture {
    /// Installs structural index semantics before signing or native capture.
    async fn new(domain: &str) -> (Self, LocalAuthority, PathBuf) {
        use terrane_format::auth::{Authority, Grant, Verbs};

        let raw = raw_fixture().await;
        let root = raw.store().root().to_owned();
        let credentials = root.with_file_name(format!(
            "{}-credentials",
            root.file_name().unwrap().to_string_lossy(),
        ));
        let owner_uid = TokioLocalFs.metadata(&root).await.unwrap().uid();
        let authority = LocalAuthority::initialize(
            &TokioLocalFs,
            &root,
            &credentials,
            LocalAuthorityParameters {
                owner_uid,
                authority: Authority {
                    issuer: "local".into(),
                    key_id: "initial".into(),
                    subject: "writer".into(),
                    kind: terrane_format::refs::PrincipalKind::Human,
                    groups: Vec::new(),
                    not_after: u64::MAX,
                    not_before: None,
                    token_id: TokioLocalFs
                        .random_bytes(16)
                        .await
                        .unwrap()
                        .try_into()
                        .unwrap(),
                    grants: vec![Grant::new("refs/**".into(), Verbs::new(31).unwrap()).unwrap()],
                    workload: None,
                },
            },
        )
        .await
        .unwrap();
        let mut policy = raw.guard().config().clone();
        policy.storage_domain = domain.into();
        drop(raw);

        // Legacy cannot author index-roots. These inputs belong to each signed
        // view and remain separate from the Guard's configured-current snapshot.
        let authoring = AuthoringNamespaceProfile::new(3, 3, &[], 2).unwrap();
        let bucket = FileBucket::open(
            config(root.clone()).await,
            TokioLocalFs,
            TokioClock,
            MetadataValidator::new(policy.chunk_profile.as_ref().clone()),
        )
        .await
        .unwrap();
        let guard = Guard::new_with_authoring_namespace_profile(
            bucket,
            TokioClock,
            vec![authority.issuer_key().clone()],
            policy,
            authoring.clone(),
        );
        let control = control(&root);
        TokioLocalFs.create_dir_new(&control).await.unwrap();
        TokioLocalFs
            .set_permissions_and_sync(&control, std::fs::Permissions::from_mode(0o700))
            .await
            .unwrap();
        let repository = Repository::initialize_native_retention(
            Coordinator::new(guard, timing(), TokioLocalFs),
            &crate::domain::DomainNamespace {
                root,
                domain: domain.into(),
            },
            &control,
            owner_uid,
        )
        .await
        .unwrap();
        (
            Self {
                repository,
                authoring,
            },
            authority,
            credentials,
        )
    }

    /// Publishes through actual preparation, Original retention and acknowledgment.
    async fn advance(
        &self,
        session: &mut crate::ref_advance::WriterSession,
        proposal: CommitRequest,
    ) -> Result<terrane_format::refs::RefRecord, crate::repository::Error> {
        self.repository.commit_request(session, proposal).await
    }

    /// Reopens actual retained Originals with the independently held profile.
    async fn reopen(self, authority: &LocalAuthority, views: &[Digest]) -> Self {
        let current_before = current_snapshot(&self.repository).await;
        let old = self.guard();
        let mut profiles = Vec::new();
        // The caller supplies the actual successful publication results. Their
        // full native histories verify independently before retaining configuration.
        for view in views.iter().copied().collect::<BTreeSet<_>>() {
            let verified = old.verified_tree(view).await.unwrap();
            assert_eq!(verified.commit.identity(), view);
            let association = RecordedAssociation::new(
                view,
                verified.commit.commit().tree,
                self.authoring.context().clone(),
            );
            let (selected, inputs) = old
                .selected_view_context_for_tests(view, verified.commit.commit().tree)
                .unwrap();
            assert_eq!(&inputs, self.authoring.registries());
            assert_eq!(
                selected,
                terrane_format::properties::selected::Selection::Recorded(
                    self.authoring.context().clone()
                )
            );
            profiles.push(
                RecordedNamespaceProfile::new(association, inputs.attribute_revision).unwrap(),
            );
        }
        let root = old.store().root().to_owned();
        let policy = old.config().clone();
        let authoring = self.authoring.clone();
        drop(self);

        let bucket = FileBucket::open(
            config(root.clone()).await,
            TokioLocalFs,
            TokioClock,
            MetadataValidator::new(policy.chunk_profile.as_ref().clone()),
        )
        .await
        .unwrap();
        let owner_uid = TokioLocalFs.metadata(&root).await.unwrap().uid();
        let domain = policy.storage_domain.clone();
        let guard = Guard::new_with_recorded_namespace_profiles_and_authoring(
            bucket,
            TokioClock,
            vec![authority.issuer_key().clone()],
            policy,
            RecordedNamespaceProfiles::new(profiles).unwrap(),
            authoring.clone(),
        );
        let repository = Repository::reopen_native_retention(
            Coordinator::new(guard, timing(), TokioLocalFs),
            &crate::domain::DomainNamespace {
                root: root.clone(),
                domain,
            },
            &control(&root),
            owner_uid,
        )
        .await
        .unwrap();
        assert_eq!(current_snapshot(&repository).await, current_before);
        Self {
            repository,
            authoring,
        }
    }

    /// Erases the real runtime source and its protected signing controls.
    async fn erase(self, credentials: PathBuf) {
        let root = self.store().root().to_owned();
        drop(self);
        for path in [control(&root), root, credentials] {
            tokio::fs::remove_dir_all(&path).await.unwrap();
            assert!(!path.exists());
        }
    }
}

/// Observes the independently captured Legacy-current snapshot under native exclusion.
async fn current_snapshot(repository: &NativeIndexRepository) -> Vec<u8> {
    let holder = crate::bucket::held::SingleHeld::acquire(repository.coordinator().store())
        .await
        .unwrap();
    let held = holder.destination();
    let observed = held.observe_publication().await.unwrap();
    let bytes = held
        .selected_guard_snapshot(&observed)
        .await
        .unwrap()
        .unwrap();
    let snapshot =
        terrane_format::gc::publication::evidence::GuardSnapshot::decode(&bytes).unwrap();
    assert_eq!(snapshot.registries.property_revision, 1);
    assert_eq!(snapshot.registries.attribute_revision, 1);
    assert!(snapshot.registries.later_properties.is_empty());
    observed.revalidate().await.unwrap();
    bytes
}

fn timing() -> CommitTiming {
    CommitTiming::new(
        Duration::from_secs(30),
        Duration::from_secs(60),
        Duration::from_secs(10),
    )
    .unwrap()
}

fn hash(domain: &[u8], bytes: &[u8]) -> Digest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&[0]);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn hex(digest: Digest) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn binding(index: Digest) -> Vec<u8> {
    let mut bytes = b"\xa2\x65value\xa1\x6bhash.sha256".to_vec();
    cbor::write_text(&mut bytes, &hex(index));
    bytes.extend_from_slice(b"\x67inherit\xf4");
    bytes
}

/// Encodes the fixture's single carrier row directly from the wire schema.
fn carrier(key: &[u8], object: Digest, route: Option<Digest>, gap: Option<Digest>) -> Vec<u8> {
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
        cbor::write_text(&mut bytes, &hex(gap));
        bytes.extend_from_slice(b"\x67inherit\xf4");
    }
    bytes
}

/// Assembles I/P/G independently for one present target and one missing graft.
fn expected_index(object: Digest, value: &[u8]) -> evaluation::IndexData {
    let mut nodes = BTreeMap::new();
    let mut stage = |bytes: Vec<u8>| {
        let root = hash(b"terrane-node-v1", &bytes);
        nodes.insert(root, bytes);
        root
    };
    let present = stage(carrier(b"target", object, None, None));
    let leaf = stage(carrier(b"file", object, None, None));
    let missing = stage(carrier(b"producer", object, Some(leaf), None));
    let gaps = stage(carrier(&object, object, Some(missing), None));
    let mut key = value.to_vec();
    key.extend(object);
    let root = stage(carrier(&key, object, Some(present), Some(gaps)));
    evaluation::IndexData {
        root,
        nodes,
        work: Default::default(),
    }
}

/// Keeps the original entry array verbatim and independently encodes new properties.
fn expected_owner(owner: &Tree<'_>, index: Digest) -> Vec<u8> {
    let mut decoder = cbor::Decoder::new(owner.root().encoded());
    assert_eq!(decoder.map(3).unwrap(), 3);
    assert_eq!(decoder.uint().unwrap(), 1);
    assert_eq!(decoder.uint().unwrap(), 0);
    assert_eq!(decoder.uint().unwrap(), 2);
    let entries = decoder.remaining();
    decoder.skip_value(entries.len()).unwrap();
    let entries = &entries[..entries.len() - decoder.remaining().len()];
    let wrapper = binding(index);
    let mut properties = owner
        .props()
        .unwrap()
        .iter()
        .filter(|property| property.name != "index-roots")
        .map(|property| (property.name, property.value))
        .collect::<Vec<_>>();
    properties.push(("index-roots", &wrapper));
    properties.sort_by(|left, right| {
        left.0
            .len()
            .cmp(&right.0.len())
            .then_with(|| left.0.cmp(right.0))
    });
    let mut bytes = vec![0xa3, 1, 0, 2];
    bytes.extend_from_slice(entries);
    bytes.push(3);
    cbor::write_map(&mut bytes, properties.len());
    for (name, value) in properties {
        cbor::write_text(&mut bytes, name);
        bytes.extend_from_slice(value);
    }
    bytes
}

fn expected_recipe(owner: Digest) -> Vec<u8> {
    let mut bytes = b"\xa3\x01\x65index\x02\x81".to_vec();
    cbor::write_bytes(&mut bytes, &owner);
    bytes.extend_from_slice(b"\x03\xa2\x67profile\x70terrane-index/v1\x69attribute\x6bhash.sha256");
    bytes
}

fn stage_index(
    authority: &LocalAuthority,
    parent: Digest,
    owner: &Tree<'_>,
    child: &Tree<'_>,
    data: &evaluation::IndexData,
    plaintext: &[u8],
    record: Option<&AttrRecord>,
) -> CommitRequest {
    let mut proposal = proposal(authority, vec![parent], owner, &[plaintext]);
    proposal
        .uploads
        .extend(child.nodes().map(|node| StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes: node.encoded().to_vec(),
        }));
    proposal
        .uploads
        .extend(data.nodes.values().map(|bytes| StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes: bytes.clone(),
        }));
    if let Some(record) = record {
        proposal.uploads.push(StagedUpload::Meta {
            kind: IdentityKind::Attribute,
            bytes: record.encode().unwrap(),
        });
    }
    proposal
}

async fn refuse_record(
    destination: &RebuildFixture,
    session: &mut crate::ref_advance::WriterSession,
    proposal: CommitRequest,
) {
    let head = destination.store().ref_get(REFERENCE).await.unwrap();
    let offered = offered(&proposal);
    let before = destination.store().has(&offered).await.unwrap();
    let physical_before = physical_snapshot(destination.store().root()).await;
    let error = storage_failure(destination.advance(session, proposal).await.unwrap_err());
    assert_eq!(
        error.kind(),
        &StoreErrorKind::Invalid(InvalidReason::MalformedRequest)
    );
    assert_eq!(destination.store().ref_get(REFERENCE).await.unwrap(), head);
    assert_eq!(destination.store().has(&offered).await.unwrap(), before);
    assert_eq!(
        physical_snapshot(destination.store().root()).await,
        physical_before
    );
}

/// Rebuilds actual I/P/G while independently enforcing current signed producer Read.
///
/// # Panics
/// Panics if native setup/admission fails, independent bytes differ, a gap closes
/// without evidence, invalid records publish, or denied producer access is reused.
pub(super) async fn rebuild_with_current_producer() {
    let (source, source_authority, credentials) = RebuildFixture::new("private:writer").await;
    let (destination, authority, _) = RebuildFixture::new("public").await;
    let plaintext = b"derived values do not confer current producer authority";
    let object = digest(IdentityKind::Chunk, plaintext);
    let private = Tree::build(
        vec![LeafItem {
            key: b"file".to_vec(),
            entry: file(plaintext),
        }],
        materialization::properties(true),
        MINIMUM,
        TreeUse::Ordinary,
    )
    .unwrap();
    let mut source_session = source
        .begin(REFERENCE, source_authority.token(), "sdk")
        .await
        .unwrap();
    let source_request = proposal(&source_authority, Vec::new(), &private, &[plaintext]);
    let private_secret = source_request.terminal_secret;
    let original = source
        .advance(&mut source_session, source_request)
        .await
        .unwrap();
    let public_child = Tree::build(
        private.iter().cloned().collect(),
        materialization::properties(false),
        MINIMUM,
        TreeUse::Ordinary,
    )
    .unwrap();
    let mut session = destination
        .begin(REFERENCE, authority.token(), "sdk")
        .await
        .unwrap();
    let introduced = destination
        .advance_disclosure(
            source.guard(),
            &mut session,
            DisclosureCommitRequest {
                proposal: proposal(&authority, Vec::new(), &public_child, &[plaintext]),
                selections: vec![DisclosureCommitSelection {
                    source_reference: REFERENCE.into(),
                    source_commit: original.commit,
                    source_path: b"/file".to_vec(),
                    source_token: source_authority.token().to_vec(),
                    destination_path: b"/file".to_vec(),
                }],
            },
        )
        .await
        .unwrap();
    let introduction = destination
        .guard()
        .read_snapshot(REFERENCE, authority.token(), b"/file", "sdk")
        .await
        .unwrap();
    let public_child = introduction
        .evidence
        .tree(introduction.evidence.root, MINIMUM)
        .unwrap();
    let public = Tree::build(
        vec![LeafItem {
            key: b"producer".to_vec(),
            entry: entry(EntryKind::Tree {
                root: public_child.root_identity(),
                props: None,
            }),
        }],
        materialization::properties(false),
        MINIMUM,
        TreeUse::Ordinary,
    )
    .unwrap();
    let mut public_request = proposal(&authority, vec![introduced.commit], &public, &[plaintext]);
    public_request
        .uploads
        .extend(public_child.nodes().map(|node| StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes: node.encoded().to_vec(),
        }));
    let secret = public_request.terminal_secret;
    let producer = destination
        .advance(&mut session, public_request)
        .await
        .unwrap();
    assert_ne!(producer.commit, introduced.commit);
    let public_snapshot = destination
        .guard()
        .read_snapshot(REFERENCE, authority.token(), b"/producer/file", "sdk")
        .await
        .unwrap();
    let (producer_location, _) = public_snapshot
        .history
        .locate(producer.commit, b"producer/file")
        .unwrap();
    let child = public_snapshot
        .evidence
        .tree(producer_location.root, MINIMUM)
        .unwrap();
    assert_eq!(
        public_snapshot
            .history
            .introducing_commit(&producer_location)
            .unwrap(),
        introduced.commit
    );
    assert!(public_snapshot.history.commit(&original.commit).is_none());
    let private_graph = [
        TERRANE_V1
            .from_digest(IdentityKind::Commit, &original.commit)
            .unwrap(),
        TERRANE_V1
            .from_digest(IdentityKind::Node, &private.root_identity())
            .unwrap(),
    ];
    assert_eq!(
        destination.store().has(&private_graph).await.unwrap(),
        [false; 2]
    );

    let observed_plaintext = destination
        .guard()
        .read_content(
            &public_snapshot,
            b"/producer/file",
            ContentRef::Inline(object),
            plaintext.len() as u64,
        )
        .await
        .unwrap();
    assert_eq!(observed_plaintext, plaintext);
    let mut hashes = PlaintextHashes::new(observed_plaintext.len() as u64);
    hashes.update(&observed_plaintext).unwrap();
    let actual_hash = hashes.finish().unwrap().sha256;
    // Independent SHA-256 oracle for the literal complete plaintext above.
    assert_eq!(
        hex(actual_hash),
        "161393a1b870b713060fee1cb0b32b0b70baad13a824b7fe1c54d336a5574657"
    );
    let value = AttributeValue::Sha256(actual_hash);
    let encoded_value = value.encode().unwrap();
    let mut record = AttrRecord::new(object, value.clone(), producer.commit);
    record.sign(&public_snapshot.commit, &secret).unwrap();
    terrane_format::derived::verify_record_producer(
        &record,
        &public_snapshot.history,
        &producer_location,
    )
    .unwrap();
    let mut target = file(plaintext);
    target.attrs_present = true;
    target.attrs.push(Attribute {
        name: ATTRIBUTE,
        value: &encoded_value,
    });
    // A valid but divergent existing binding supplies no relation proof.
    let wrong_bytes = vec![0xa2, 1, 0, 2, 0x80];
    let wrong_root = hash(b"terrane-node-v1", &wrong_bytes);
    let wrong_data = evaluation::IndexData {
        root: wrong_root,
        nodes: BTreeMap::from([(wrong_root, wrong_bytes)]),
        work: Default::default(),
    };
    let wrong_binding = binding(wrong_root);
    let mut candidate_properties = materialization::properties(false).unwrap();
    candidate_properties.push(Property {
        name: "index-roots",
        value: &wrong_binding,
    });
    let candidate = Tree::build(
        vec![
            LeafItem {
                key: b"producer".to_vec(),
                entry: entry(EntryKind::Tree {
                    root: child.root_identity(),
                    props: None,
                }),
            },
            LeafItem {
                key: b"target".to_vec(),
                entry: target,
            },
        ],
        Some(candidate_properties),
        MINIMUM,
        TreeUse::Ordinary,
    )
    .unwrap();
    let graph = BTreeMap::from([
        (candidate.root_identity(), candidate.clone()),
        (child.root_identity(), child.clone()),
    ]);
    let context = SemanticContext::new(3, 2, 1).unwrap();
    let recipe = IndexEvaluationRecipe::new(candidate.root_identity(), ATTRIBUTE).unwrap();
    assert_eq!(
        evaluation::verify(&recipe, &graph, MINIMUM, context, &wrong_data),
        Err(evaluation::Error::Relationship)
    );
    let prepared = incremental::PreparedSource::new(&recipe, &graph, MINIMUM, context).unwrap();
    let arena = maintenance::ByteArena::new(1 << 20).unwrap();
    let (state, construction) =
        maintenance::rebuild(&recipe, &prepared, &arena, MINIMUM, context).unwrap();
    let (data, export) = state.materialize().unwrap();
    let expected = expected_index(object, &encoded_value);
    assert_eq!(data.root, expected.root);
    assert_eq!(data.nodes, expected.nodes);
    assert_eq!(data.nodes.len(), 5);
    assert_eq!(construction.kind, maintenance::ConstructionKind::Rebuild);
    assert!(export.nodes > 0);
    let verified = evaluation::verify(&recipe, &graph, MINIMUM, context, &data).unwrap();
    assert_eq!(verified.candidates, 1);
    assert_eq!(verified.missing_objects, 1);
    let mut corrupt = data.clone();
    corrupt.nodes.insert(data.root, vec![0xf6]);
    assert_eq!(
        evaluation::verify(&recipe, &graph, MINIMUM, context, &corrupt),
        Err(evaluation::Error::Relationship)
    );
    assert!(matches!(
        completion::complete(
            candidate.root_identity(),
            &graph,
            &[completion::Selection {
                attribute: ATTRIBUTE,
                data: &corrupt
            }],
            &arena,
            MINIMUM,
            context,
            completion::MemoPolicy::Include
        ),
        Err(completion::Error::Index(evaluation::Error::Relationship))
    ));

    let completed = completion::complete(
        candidate.root_identity(),
        &graph,
        &[completion::Selection {
            attribute: ATTRIBUTE,
            data: &data,
        }],
        &arena,
        MINIMUM,
        context,
        completion::MemoPolicy::Include,
    )
    .unwrap();
    let expected_owner = expected_owner(&candidate, data.root);
    assert_eq!(completed.owner.tree.root().encoded(), expected_owner);
    assert_eq!(
        completed.owner.tree.root_identity(),
        hash(b"terrane-node-v1", &expected_owner)
    );
    assert_eq!(candidate.root_identity(), recipe.owner());
    assert_eq!(
        candidate
            .props()
            .unwrap()
            .iter()
            .find(|property| property.name == "index-roots")
            .unwrap()
            .value,
        wrong_binding
    );
    let association = &completed.associations[0];
    let expected_recipe = expected_recipe(completed.owner.tree.root_identity());
    assert_eq!(association.recipe_bytes, expected_recipe);
    assert_eq!(
        association.recipe_hash,
        hash(b"terrane-memo-v1", &expected_recipe)
    );
    let mut memo = vec![0xa2, 1];
    cbor::write_bytes(&mut memo, &association.recipe_hash);
    memo.push(2);
    cbor::write_bytes(&mut memo, &data.root);
    assert_eq!(association.memo.as_ref().unwrap().bytes, memo);
    assert_eq!(
        association.memo.as_ref().unwrap().identity,
        hash(b"terrane-memo-v1", &memo)
    );
    assert_eq!(completed.work.checks[0].before.missing_objects, 1);

    // Identical immutable owner bytes and plaintext cannot repair producer proof.
    let mut forged = record.clone();
    forged.signature.as_mut().unwrap()[0] ^= 1;
    refuse_record(
        &destination,
        &mut session,
        stage_index(
            &authority,
            producer.commit,
            &completed.owner.tree,
            &child,
            &data,
            plaintext,
            Some(&forged),
        ),
    )
    .await;
    let mut unsigned = record.clone();
    unsigned.signature = None;
    refuse_record(
        &destination,
        &mut session,
        stage_index(
            &authority,
            producer.commit,
            &completed.owner.tree,
            &child,
            &data,
            plaintext,
            Some(&unsigned),
        ),
    )
    .await;
    let mut wrong_object = record.clone();
    wrong_object.object = [0x45; 32];
    wrong_object.sign(&public_snapshot.commit, &secret).unwrap();
    refuse_record(
        &destination,
        &mut session,
        stage_index(
            &authority,
            producer.commit,
            &completed.owner.tree,
            &child,
            &data,
            plaintext,
            Some(&wrong_object),
        ),
    )
    .await;
    let private_snapshot = source
        .guard()
        .read_snapshot(REFERENCE, source_authority.token(), b"/file", "sdk")
        .await
        .unwrap();
    let mut private_record = AttrRecord::new(object, value, original.commit);
    private_record
        .sign(&private_snapshot.commit, &private_secret)
        .unwrap();
    let private_offer = stage_index(
        &authority,
        producer.commit,
        &completed.owner.tree,
        &child,
        &data,
        plaintext,
        Some(&private_record),
    );
    let private_ids = offered(&private_offer);
    let before = destination.store().has(&private_ids).await.unwrap();
    let physical_before = physical_snapshot(destination.store().root()).await;
    let error = storage_failure(
        destination
            .advance(&mut session, private_offer)
            .await
            .unwrap_err(),
    );
    assert_eq!(
        error.kind(),
        &StoreErrorKind::Absent(
            TERRANE_V1
                .from_digest(IdentityKind::Commit, &original.commit)
                .unwrap()
        )
    );
    assert_eq!(
        destination.store().ref_get(REFERENCE).await.unwrap(),
        Some(producer.clone())
    );
    assert_eq!(destination.store().has(&private_ids).await.unwrap(), before);
    assert_eq!(
        physical_snapshot(destination.store().root()).await,
        physical_before
    );
    drop(private_snapshot);

    let rebuilt = destination
        .advance(
            &mut session,
            stage_index(
                &authority,
                producer.commit,
                &completed.owner.tree,
                &child,
                &data,
                plaintext,
                Some(&record),
            ),
        )
        .await
        .unwrap();
    let raw = crate::indexing::load(
        destination.store(),
        completed.owner.tree.root_identity(),
        ATTRIBUTE,
        crate::indexing::SemanticRevisions {
            property: 3,
            attribute: 2,
            tree: 1,
        },
        MINIMUM,
    )
    .await
    .unwrap();
    assert_eq!(raw.index_root(), data.root);
    let sources = raw.sources().unwrap();
    let prepared = raw.prepare(&sources.trees).unwrap();
    let candidates = prepared.candidates(&encoded_value).unwrap();
    assert_eq!(candidates.rows.len(), 1);
    assert_eq!(candidates.rows[0].object(), object);
    let occurrences = candidates.rows[0].occurrences().unwrap();
    assert_eq!(occurrences.rows.len(), 1);
    assert_eq!(occurrences.rows[0].key, b"target");
    let gaps = prepared.all_missing().unwrap();
    assert_eq!(gaps.rows.len(), 1);
    let missing = gaps.rows[0].occurrences().unwrap();
    assert_eq!(missing.rows.len(), 1);
    assert_eq!(missing.rows[0].hops[0].key, b"producer");
    assert_eq!(missing.rows[0].key, b"file");
    let checked = destination
        .guard()
        .read_snapshot(REFERENCE, authority.token(), b"/target", "sdk")
        .await
        .unwrap();
    let (target_location, _) = checked.history.locate(rebuilt.commit, b"target").unwrap();
    assert_eq!(
        checked
            .history
            .introducing_commit(&target_location)
            .unwrap(),
        rebuilt.commit
    );
    assert_eq!(
        checked
            .history
            .attribute_producer(&target_location, ATTRIBUTE)
            .unwrap(),
        rebuilt.commit
    );
    let carried = destination
        .guard()
        .read_snapshot(REFERENCE, authority.token(), b"/producer/file", "sdk")
        .await
        .unwrap();
    let (carried_location, _) = carried
        .history
        .locate(rebuilt.commit, b"producer/file")
        .unwrap();
    assert_eq!(
        carried
            .history
            .introducing_commit(&carried_location)
            .unwrap(),
        introduced.commit
    );
    assert_ne!(introduced.commit, record.producer);
    drop(carried);
    record
        .verify_signature(&public_snapshot.commit.signing_public_key())
        .unwrap();
    drop(checked);
    drop(source_session);
    drop(source_authority);
    source.erase(credentials).await;
    drop(session);
    let destination = destination
        .reopen(
            &authority,
            &[introduced.commit, producer.commit, rebuilt.commit],
        )
        .await;
    assert_eq!(
        destination.store().has(&private_graph).await.unwrap(),
        [false; 2]
    );
    let raw = crate::indexing::load(
        destination.store(),
        completed.owner.tree.root_identity(),
        ATTRIBUTE,
        crate::indexing::SemanticRevisions {
            property: 3,
            attribute: 2,
            tree: 1,
        },
        MINIMUM,
    )
    .await
    .unwrap();
    assert_eq!(raw.index_root(), data.root);
    let sources = raw.sources().unwrap();
    let prepared = raw.prepare(&sources.trees).unwrap();
    assert_eq!(
        prepared.candidates(&encoded_value).unwrap().rows[0].object(),
        object
    );
    let checked = destination
        .guard()
        .read_snapshot(REFERENCE, authority.token(), b"/target", "sdk")
        .await
        .unwrap();
    assert_eq!(checked.commit.identity(), rebuilt.commit);
    let owner = checked
        .evidence
        .tree(checked.evidence.root, MINIMUM)
        .unwrap();
    // AUTH-22 makes mutation verbs imply Read, so producer grants must be
    // removed. The independent target remains governed by root writer15.
    let mut child_properties = child.props().unwrap().to_vec();
    child_properties
        .iter_mut()
        .find(|property| property.name == "acl")
        .unwrap()
        .value = b"\x81\x82\x66writer\x00";
    let denied_child = child.with_properties(Some(child_properties)).unwrap().tree;
    let mut root_properties = owner.props().unwrap().to_vec();
    root_properties
        .iter_mut()
        .find(|property| property.name == "acl")
        .unwrap()
        .value = b"\x81\x82\x66writer\x0f";
    let mut entries = owner.iter().cloned().collect::<Vec<_>>();
    entries
        .iter_mut()
        .find(|item| item.key == b"producer")
        .unwrap()
        .entry
        .kind = EntryKind::Tree {
        root: denied_child.root_identity(),
        props: None,
    };
    let denied_owner =
        Tree::build(entries, Some(root_properties), MINIMUM, TreeUse::Ordinary).unwrap();
    let denied_graph = BTreeMap::from([
        (denied_owner.root_identity(), denied_owner.clone()),
        (denied_child.root_identity(), denied_child.clone()),
    ]);
    evaluation::verify(
        &IndexEvaluationRecipe::new(denied_owner.root_identity(), ATTRIBUTE).unwrap(),
        &denied_graph,
        MINIMUM,
        context,
        &data,
    )
    .unwrap();
    let mut session = destination
        .begin(REFERENCE, authority.token(), "sdk")
        .await
        .unwrap();
    let narrowed = destination
        .advance(
            &mut session,
            stage_index(
                &authority,
                rebuilt.commit,
                &denied_owner,
                &denied_child,
                &data,
                plaintext,
                None,
            ),
        )
        .await
        .unwrap();
    destination
        .guard()
        .authorize(
            REFERENCE,
            authority.token(),
            terrane_format::auth::Verb::Commit,
            &[b"/target".to_vec()],
            "sdk",
        )
        .await
        .unwrap();
    destination
        .guard()
        .read_snapshot(REFERENCE, authority.token(), b"/target", "sdk")
        .await
        .unwrap();
    let denied_producer = destination
        .guard()
        .read_commit_snapshot(producer.commit, authority.token(), b"/producer/file", "sdk")
        .await;
    assert!(matches!(
        denied_producer,
        Err(error) if matches!(error.kind(), StoreErrorKind::Denied { verb: "read", .. })
    ));
    refuse_record(
        &destination,
        &mut session,
        stage_index(
            &authority,
            narrowed.commit,
            &denied_owner,
            &denied_child,
            &data,
            plaintext,
            Some(&record),
        ),
    )
    .await;
    assert_eq!(
        destination.store().ref_get(REFERENCE).await.unwrap(),
        Some(narrowed)
    );
    assert_eq!(data.root, expected.root);
    assert_eq!(data.nodes, expected.nodes);
}
