//! Checks independently authored manifests against complete source and destination histories.

use super::*;
use crate::domain::DomainNamespace;
use crate::repository::local_authority::{LocalAuthority, LocalAuthorityParameters};
use crate::repository::{MetadataValidator, Repository};
use crate::store::{ChunkPosition, LocalFs};
use std::collections::BTreeMap;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use terrane_format::auth::{Authority, Grant, Verbs};
use terrane_format::chunking::ChunkProfile;
use terrane_format::manifest::{ChunkRef, Manifest};
use terrane_format::tree_format::Attribute;

type NativeRepository =
    Repository<FileBucket<TokioLocalFs, TokioClock, MetadataValidator>, TokioClock, TokioLocalFs>;

/// Supplies an actual protected repository with genuine receiver validation.
pub(super) struct Factory {
    /// Repository whose backend validates encoded plaintext and metadata.
    pub(super) repository: NativeRepository,
    /// Independently generated host-held current signing credentials.
    pub(super) authority: LocalAuthority,
}

/// Initializes genuine protected authority and a metadata-validating backend.
///
/// # Panics
/// Panics if native physical setup, credential generation, or registration fails.
pub(super) async fn factory() -> Factory {
    let raw = raw_fixture().await;
    let root = raw.store().root().to_owned();
    let guard_config = raw.guard().config().clone();
    let credentials = root.with_file_name(format!(
        "{}-credentials",
        root.file_name().unwrap().to_string_lossy(),
    ));
    let owner = TokioLocalFs.metadata(&root).await.unwrap().uid();
    let authority = LocalAuthority::initialize(
        &TokioLocalFs,
        &root,
        &credentials,
        LocalAuthorityParameters {
            owner_uid: owner,
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
    drop(raw);

    let bucket = FileBucket::open(
        config(root.clone()).await,
        TokioLocalFs,
        TokioClock,
        MetadataValidator::new(ChunkProfile::cdc_1m([0; 32])),
    )
    .await
    .unwrap();
    let coordinator = Coordinator::new(
        Guard::new(
            bucket,
            TokioClock,
            vec![authority.issuer_key().clone()],
            guard_config,
        ),
        CommitTiming::new(
            Duration::from_secs(30),
            Duration::from_secs(60),
            Duration::from_secs(10),
        )
        .unwrap(),
        TokioLocalFs,
    );
    let control = root.with_file_name(format!(
        "{}-original-control",
        root.file_name().unwrap().to_string_lossy(),
    ));
    TokioLocalFs.create_dir_new(&control).await.unwrap();
    TokioLocalFs
        .set_permissions_and_sync(&control, std::fs::Permissions::from_mode(0o700))
        .await
        .unwrap();
    let repository = Repository::initialize_native_retention(
        coordinator,
        &DomainNamespace {
            root,
            domain: "public".into(),
        },
        &control,
        owner,
    )
    .await
    .unwrap();
    Factory {
        repository,
        authority,
    }
}

fn file(content: ContentRef, size: usize) -> Entry<'static> {
    Entry {
        kind: EntryKind::File {
            mode: 0o644,
            size: size as u64,
            content,
            link_id: None,
        },
        attrs: vec![Attribute {
            name: "note",
            value: b"\x61x",
        }],
        attrs_present: true,
        xattrs: Vec::new(),
        xattrs_present: false,
        provenance: None,
    }
}

fn tree(entries: Vec<LeafItem<'static>>) -> Tree<'static> {
    Tree::build(
        entries,
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
    .unwrap()
}

fn manifest_request(plaintext: &[u8]) -> (super::super::CommitRequest, ContentRef) {
    let profile = ChunkProfile::cdc_1m([0; 32]);
    let ranges = profile.ranges(plaintext).collect::<Vec<_>>();
    let mut uploads = Vec::new();
    let mut chunks = Vec::new();
    for (index, range) in ranges.iter().enumerate() {
        let bytes = &plaintext[range.clone()];
        let identity = TERRANE_V1.calculate(IdentityKind::Chunk, bytes).unwrap();
        chunks.push(ChunkRef {
            digest: identity.terrane_v1_digest().unwrap(),
            length: bytes.len() as u64,
        });
        uploads.push(StagedUpload::Chunk {
            encoded: terrane_format::codec::encode_envelope(terrane_format::codec::EncodedChunk {
                codec: terrane_format::codec::Codec::Raw,
                body: bytes,
            }),
            identity,
            declared_plaintext_len: bytes.len(),
            position: if index + 1 == ranges.len() {
                ChunkPosition::Final
            } else {
                ChunkPosition::NonFinal
            },
            profile: Box::new(profile.clone()),
        });
    }
    let manifest = Manifest {
        size: plaintext.len() as u64,
        chunks,
        hashes: BTreeMap::from([("blake3".into(), blake3::hash(plaintext).as_bytes().to_vec())]),
        media_type: Some("application/octet-stream".into()),
    };
    let content = ContentRef::Manifest(
        manifest
            .identity(&profile)
            .unwrap()
            .terrane_v1_digest()
            .unwrap(),
    );
    uploads.push(StagedUpload::Meta {
        kind: IdentityKind::Manifest,
        bytes: manifest.encode(&profile).unwrap(),
    });
    let tree = tree(vec![LeafItem {
        key: b"file".to_vec(),
        entry: file(content, plaintext.len()),
    }]);
    uploads.extend(tree.nodes().map(|node| StagedUpload::Meta {
        kind: IdentityKind::Node,
        bytes: node.encoded().to_vec(),
    }));
    let mut proposal = request(Vec::new());
    proposal.commit.tree = tree.root_identity();
    proposal.uploads = uploads;
    (proposal, content)
}

/// Checks two independently published manifests through certified disclosure and destination reads.
///
/// # Panics
/// Panics if native setup, manifest construction, publication or reads fail, or
/// if distinct authorities, certificates, retained histories or file contents
/// contradict the fixture assertions.
pub(super) async fn publish_independent_manifests() {
    use super::super::{DisclosureCommitRequest, DisclosureCommitSelection};

    let source = factory().await;
    let destination = factory().await;
    assert_ne!(
        source.authority.issuer_key().public_key,
        destination.authority.issuer_key().public_key
    );
    let payloads = [vec![0x39; 300_001], vec![0x7a; 350_003]];
    let references = ["refs/heads/_/left", "refs/heads/_/right"];
    let mut heads = Vec::new();
    let mut contents = Vec::new();
    for (reference, plaintext) in references.iter().zip(&payloads) {
        let mut session = source
            .repository
            .begin(reference, source.authority.token(), "sdk")
            .await
            .unwrap();
        let (unsigned, content) = manifest_request(plaintext);
        let mut proposal = source
            .authority
            .commit_request(unsigned.commit, "sdk".into());
        proposal.uploads = unsigned.uploads;
        heads.push(
            source
                .repository
                .commit_request(&mut session, proposal)
                .await
                .unwrap(),
        );
        contents.push(content);
    }
    assert_ne!(heads[0].commit, heads[1].commit);

    let reference = "refs/heads/_/main";
    let mut session = destination
        .repository
        .begin(reference, destination.authority.token(), "sdk")
        .await
        .unwrap();
    let unsigned = request(Vec::new());
    let mut baseline = destination
        .authority
        .commit_request(unsigned.commit, "sdk".into());
    baseline.uploads = unsigned.uploads;
    let previous = destination
        .repository
        .commit_request(&mut session, baseline)
        .await
        .unwrap();
    let target = tree(vec![
        LeafItem {
            key: b"left".to_vec(),
            entry: file(contents[0], payloads[0].len()),
        },
        LeafItem {
            key: b"right".to_vec(),
            entry: file(contents[1], payloads[1].len()),
        },
    ]);
    let mut unsigned = request(vec![previous.commit]);
    unsigned.commit.tree = target.root_identity();
    let mut proposal = destination
        .authority
        .commit_request(unsigned.commit, "sdk".into());
    proposal.uploads = target
        .nodes()
        .map(|node| StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes: node.encoded().to_vec(),
        })
        .collect();
    let published = destination
        .repository
        .commit_disclosure(
            &source.repository,
            &mut session,
            DisclosureCommitRequest {
                selections: references
                    .iter()
                    .enumerate()
                    .map(|(index, reference)| DisclosureCommitSelection {
                        source_reference: (*reference).into(),
                        source_commit: heads[index].commit,
                        source_path: b"/file".to_vec(),
                        source_token: source.authority.token().to_vec(),
                        destination_path: if index == 0 {
                            b"/left".to_vec()
                        } else {
                            b"/right".to_vec()
                        },
                    })
                    .collect(),
                proposal,
            },
        )
        .await
        .unwrap();

    for (index, path) in [b"/left".as_slice(), b"/right".as_slice()]
        .iter()
        .enumerate()
    {
        let guard = destination.repository.coordinator().guard();
        let snapshot = guard
            .read_snapshot(reference, destination.authority.token(), path, "sdk")
            .await
            .unwrap();
        assert_eq!(snapshot.commit.identity(), published.commit);
        let receipts = snapshot
            .commit
            .commit()
            .profile_pair
            .entry_receipts
            .as_ref()
            .unwrap();
        let certified = receipts
            .iter()
            .filter(|receipt| receipt.disclosure_proof.is_some())
            .collect::<Vec<_>>();
        assert_eq!(certified.len(), 2);
        for (receipt, head) in certified.iter().zip(&heads) {
            assert_eq!(
                receipt.reintroduced_from.as_ref().unwrap().commit,
                head.commit
            );
            let proof = receipt.disclosure_proof.as_ref().unwrap();
            assert_eq!(proof.source_domain, "public");
            assert_ne!(proof.signature, [0; 64]);
        }
        assert_ne!(
            certified[0].disclosure_proof.as_ref().unwrap().signature,
            certified[1].disclosure_proof.as_ref().unwrap().signature,
        );
        assert!(snapshot.history.commit(&previous.commit).is_some());
        for head in &heads {
            assert!(snapshot.history.commit(&head.commit).is_some());
        }
        let (location, _) = snapshot
            .history
            .locate(published.commit, &path[1..])
            .unwrap();
        let entry = snapshot.history.entry(&location).unwrap();
        let EntryKind::File { content, size, .. } = entry.kind else {
            panic!("manifest file expected")
        };
        assert_eq!(content, contents[index]);
        assert_eq!(
            guard
                .read_content(&snapshot, path, content, size)
                .await
                .unwrap(),
            payloads[index]
        );
    }
}
