//! Publishes a genuine required-index source before refusing its auxiliary read.
//!
//! A fresh configured factory supplies the recorded profile. Finite literal I/P
//! bytes predict this one-file index independently of production index builders.
//! Missing bindings remain permitted incomplete lookups under DRV-27; this case
//! instead refuses a read of an actually present, completed required binding.

use super::*;

use crate::bucket::{FileBucketConfig, FileBucketPublicationConfig};
use crate::domain::DomainNamespace;
use crate::guard::Guard;
use crate::ref_advance::{Coordinator, StagedUpload};
use std::os::unix::fs::PermissionsExt;
use terrane_format::identity::Identity;
use terrane_format::tree_format::Attribute;

type ExpectedIndex = ([u8; 32], BTreeMap<[u8; 32], Vec<u8>>);

const BODY: &[u8] = b"required-index immutable body";

#[tokio::test]
async fn requalification_refuses_actual_required_index_read_failure() -> TestResult {
    let (fixture, primary) = indexed_source().await?;
    let before = SourceSnapshot::capture(&fixture.repository, &fixture.clock, SOURCE).await?;
    calibrate(&fixture.repository, fixture.root).await?;
    let store = fixture.repository.coordinator().store();
    let primary_identity = TERRANE_V1.from_digest(IdentityKind::Node, &primary)?;
    let commit_identity = TERRANE_V1.from_digest(IdentityKind::Commit, &before.record.commit)?;
    let root_identity = TERRANE_V1.from_digest(IdentityKind::Node, &fixture.root)?;
    let pack = actual_pack(&fixture, &primary_identity).await?;
    let commit_pack = actual_pack(&fixture, &commit_identity).await?;
    let root_pack = actual_pack(&fixture, &root_identity).await?;
    assert_ne!(
        pack, commit_pack,
        "the auxiliary fault must spare source history"
    );
    assert_ne!(
        pack, root_pack,
        "the auxiliary fault must spare namespace authorization"
    );

    fixture.fs.block_requalification_pack(pack)?;
    fixture
        .fs
        .observe_requalification_ack(before.ack_slot(), false)?;
    fixture.fs.observe_requalification_effects()?;
    fixture.fs.effects.store(0, Ordering::SeqCst);

    let failure = fixture
        .repository
        .requalify_fork_source(SOURCE, fixture.authority.token(), "sdk")
        .await
        .err()
        .ok_or("unavailable required index accepted")?;

    assert!(
        matches!(
            store_failure(&failure)?.kind(),
            StoreErrorKind::Unavailable { .. }
        ),
        "{failure:?}"
    );

    let mut diagnostic = std::error::Error::source(store_failure(&failure)?);
    let mut index_failure = None;
    while let Some(source) = diagnostic {
        if let Some(error) = source.downcast_ref::<crate::indexing::Error>() {
            index_failure = Some(error);
            break;
        }
        diagnostic = source.source();
    }
    assert!(
        matches!(index_failure, Some(crate::indexing::Error::Store { node, .. }) if *node == primary),
        "the exact required primary must fail through the owning index check: {failure:?}"
    );
    let index_failure = index_failure.ok_or("missing owning index diagnostic")?;
    let underlying = std::error::Error::source(index_failure)
        .and_then(|source| source.downcast_ref::<StoreFailure>())
        .ok_or("missing original auxiliary store failure")?;
    assert_eq!(underlying.kind(), store_failure(&failure)?.kind());
    // Containing-pack reads share the original failure with other consumers.
    // Follow those diagnostic wrappers to the actual injected filesystem error.
    let mut diagnostic = std::error::Error::source(underlying);
    let mut io = None;
    while let Some(source) = diagnostic {
        if let Some(error) = source.downcast_ref::<std::io::Error>() {
            io = Some(error);
            break;
        }
        diagnostic = source.source();
    }
    let io = io.ok_or("missing actual auxiliary pack I/O diagnostic")?;
    assert_eq!(io.kind(), std::io::ErrorKind::Other);
    assert_eq!(
        io.to_string(),
        "actual required-index pack read unavailable"
    );

    assert!(
        fixture.fs.blocked_requalification_reads() > 0,
        "actual auxiliary body storage must be attempted"
    );
    assert_eq!(fixture.fs.requalification_ack_counts(), (0, 0));
    assert_eq!(fixture.fs.effects.load(Ordering::SeqCst), 1);
    assert_eq!(
        fixture.fs.requalification_effect_observations()?,
        vec![("DirectorySync", Some(store.root().to_owned()))]
    );
    let after = SourceSnapshot::capture(&fixture.repository, &fixture.clock, SOURCE).await?;
    assert_eq!(after.state, before.state);
    assert_eq!(after.logical, before.logical);
    before
        .assert_source_unchanged(&fixture.repository, &fixture.fs, SOURCE)
        .await?;
    Ok(())
}

// Each lookup starts with fresh physical observations. The Commit and namespace
// may share a native metadata pack; neither may share the faulted auxiliary pack.
async fn actual_pack(fixture: &Fixture, identity: &Identity) -> TestResult<PathBuf> {
    fixture.fs.clear_requalification_pack_reads()?;
    fixture
        .repository
        .coordinator()
        .store()
        .get(identity, None)
        .await?;
    let actual = fixture.fs.requalification_pack_reads()?;
    assert_eq!(
        actual.len(),
        1,
        "the exact lookup must identify one actual pack"
    );
    actual
        .into_iter()
        .next()
        .ok_or_else(|| "missing actual content pack".into())
}

async fn indexed_source() -> TestResult<(Fixture, [u8; 32])> {
    let seed = Fixture::open().await?;
    let parent = seed
        .location
        .bucket
        .parent()
        .ok_or("missing private fixture directory")?;
    let root = parent.join("indexed-bucket");
    let control = parent.join("indexed-authority");
    seed.fs.create_dir_new(&control).await?;
    seed.fs
        .set_permissions_and_sync(&control, std::fs::Permissions::from_mode(0o700))
        .await?;
    let owner = seed.fs.symlink_metadata(&control).await?.uid();
    let configured = seed.repository.coordinator().guard().config().clone();
    let bucket = FileBucket::open(
        FileBucketConfig {
            root: root.clone(),
            publication_control: Some(FileBucketPublicationConfig {
                operator_uid: owner,
                control: None,
            }),
            chunk_profile_name: configured.chunk_profile_name.clone(),
            chunk_profile: (*configured.chunk_profile).clone(),
            locality: configured.home.clone(),
        },
        seed.fs.clone(),
        seed.clock.clone(),
        MetadataValidator::new((*configured.chunk_profile).clone()),
    )
    .await?;
    // This is a fresh actual native repository, not a same-root Guard update or
    // a caller-provided profile substituted for a completed signed source.
    let guard = Guard::new_active(
        bucket,
        seed.clock.clone(),
        seed.repository.coordinator().guard().keys().to_vec(),
        configured,
    )
    .with_recorded_authoring(
        terrane_format::properties::semantics::RecordedContext::new(3, 3, &[])?,
        2,
    )?;
    let repository = Repository::initialize_native_retention(
        Coordinator::new(guard, timing()?, seed.fs.clone()),
        &DomainNamespace {
            root: root.clone(),
            domain: "private:owner".into(),
        },
        &control,
        owner,
    )
    .await?;
    let directory = parent.join("indexed-source");
    seed.fs.create_dir_new(&directory).await?;
    seed.fs.write_new(&directory.join("file"), BODY).await?;
    let imported =
        crate::repository::import_directory(&seed.fs, &directory, repository.chunk_profile(), &[])
            .await?;
    let (primary, nodes) = expected_index()?;
    let prepared = {
        let uid = vec![1];
        let imported_tree = imported.tree()?;
        let mut entries = imported_tree.iter().cloned().collect::<Vec<_>>();
        assert_eq!(entries.len(), 1);
        let entry = entries.first_mut().ok_or("missing actual imported file")?;
        entry.entry.attrs = vec![Attribute {
            name: "uid",
            value: &uid,
        }];
        let mut acl = Vec::new();
        cbor::write_array(&mut acl, 1);
        cbor::write_array(&mut acl, 2);
        cbor::write_text(&mut acl, "owner");
        cbor::write_uint(&mut acl, 31);
        let domain = text("private:owner");
        let required = vec![0x81, 0x63, b'u', b'i', b'd'];
        let roots = wrapper(map(vec![("uid", text(&hex(primary)))]));
        let mut properties = vec![
            Property {
                name: "acl",
                value: &acl,
            },
            Property {
                name: "domain",
                value: &domain,
            },
            Property {
                name: "index",
                value: &required,
            },
            Property {
                name: "index-roots",
                value: &roots,
            },
        ];
        properties.sort_by(|left, right| {
            (left.name.len(), left.name).cmp(&(right.name.len(), right.name))
        });
        let tree = Tree::build(
            entries,
            Some(properties),
            repository.chunk_profile().minimum() as u64,
            TreeUse::Ordinary,
        )?;
        PreparedTree::from_tree(&tree)?
    };

    // Ordinary native puts select the independent finite I/P bytes before the
    // source's metadata batch. The batch can reuse them without co-packing the
    // required primary with its owner or signed Commit.
    for (digest, bytes) in &nodes {
        let identity = repository
            .coordinator()
            .store()
            .put(crate::store::ContentUpload::Meta(
                crate::store::MetaUpload::new(IdentityKind::Node, bytes)?,
            ))
            .await?;
        assert_eq!(identity.terrane_v1_digest()?, *digest);
    }

    let mut request = repository.source_request(
        &seed.authority,
        metadata("Publish real required-index source"),
    );
    request.commit.tree = prepared.root();
    request.commit.parents.clear();
    request
        .uploads
        .extend(imported.uploads.into_iter().filter(|upload| {
            !matches!(
                upload,
                StagedUpload::Meta {
                    kind: IdentityKind::Node,
                    ..
                }
            )
        }));
    let mut session = repository
        .begin(SOURCE, seed.authority.token(), "sdk")
        .await?;
    let report = repository
        .commit_with_report(&mut session, prepared, request)
        .await?;
    assert_eq!(report.index_work.operations.len(), 1);
    let operation = &report.index_work.operations[0];
    assert!(operation.initialization.is_some());
    assert_eq!(operation.association.index, primary);
    let record = report.record;
    let (lineage, _) = selected_fixture_lineage(&repository, &seed.clock, SOURCE).await?;
    assert!(lineage.used.check_supported_view_contexts()?);
    let root_identity = terrane_format::refs::Commit::decode(&lineage.commit_bytes)?.tree;
    let Fixture {
        authority,
        fs,
        clock,
        _directory,
        ..
    } = seed;
    Ok((
        Fixture {
            repository,
            authority,
            record,
            root: root_identity,
            fs,
            clock,
            location: LocalRepositoryLocation {
                bucket: root,
                authority: control,
            },
            _directory,
        },
        primary,
    ))
}

// These finite literal bytes match the independently published one-file I/P
// vectors used by the ordinary writer's owning tests. No signed data is forged.
fn expected_index() -> TestResult<ExpectedIndex> {
    let object = TERRANE_V1
        .calculate(IdentityKind::Chunk, BODY)?
        .terrane_v1_digest()?;
    let mut nodes = BTreeMap::new();
    let mut terminal = vec![0xa2, 1, 7, 14, 0x81];
    cbor::write_bytes(&mut terminal, &object);
    let route_bytes = leaf(&[(b"file".to_vec(), terminal)]);
    let route = TERRANE_V1
        .calculate(IdentityKind::Node, &route_bytes)?
        .terrane_v1_digest()?;
    nodes.insert(route, route_bytes);
    let mut forward = vec![0xa3, 1, 7, 9, 0xa1];
    cbor::write_text(&mut forward, "index.occurrences");
    cbor::write_bytes(&mut forward, &route);
    forward.extend_from_slice(&[14, 0x81]);
    cbor::write_bytes(&mut forward, &object);
    let mut key = vec![1];
    key.extend_from_slice(&object);
    let primary_bytes = leaf(&[(key, forward)]);
    let primary = TERRANE_V1
        .calculate(IdentityKind::Node, &primary_bytes)?
        .terrane_v1_digest()?;
    nodes.insert(primary, primary_bytes);
    Ok((primary, nodes))
}

fn leaf(rows: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut out = vec![0xa2, 1, 0, 2];
    cbor::write_array(&mut out, rows.len());
    let mut previous: &[u8] = &[];
    for (key, entry) in rows {
        let shared = key
            .iter()
            .zip(previous)
            .take_while(|(left, right)| left == right)
            .count();
        out.push(0x83);
        cbor::write_bytes(&mut out, &key[shared..]);
        cbor::write_uint(&mut out, shared as u64);
        out.extend(entry);
        previous = key;
    }
    out
}

fn map(mut entries: Vec<(&str, Vec<u8>)>) -> Vec<u8> {
    entries.sort_by(|(left, _), (right, _)| (left.len(), *left).cmp(&(right.len(), *right)));
    let mut out = Vec::new();
    cbor::write_map(&mut out, entries.len());
    for (name, value) in entries {
        cbor::write_text(&mut out, name);
        out.extend(value);
    }
    out
}

fn wrapper(value: Vec<u8>) -> Vec<u8> {
    map(vec![("inherit", vec![0xf4]), ("value", value)])
}

fn text(value: &str) -> Vec<u8> {
    let mut out = Vec::new();
    cbor::write_text(&mut out, value);
    out
}

fn hex(digest: [u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}
