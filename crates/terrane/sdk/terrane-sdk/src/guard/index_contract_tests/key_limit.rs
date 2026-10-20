//! Checks real parsed shebang values against durable publication at the exact key cap.

use std::collections::BTreeMap;
use std::error::Error as _;
use std::path::{Path, PathBuf};

use super::native_fixture::{Fixture, NativeRepository, REFERENCE, TestResult};
use crate::derived::AttributeCatalog;
use crate::guard::{CommitRequest, StagedUpload, TreeEvidence, invalid};
use crate::indexing::{self, SemanticRevisions};
use crate::repository::PreparedTree;
use crate::store::{ContentStore, LocalFs, RefStore, TokioLocalFs};
use terrane_format::{
    cbor,
    derived::{AttrRecord, AttributeValue, Magic, classify_magic, parse_shebang},
    identity::{Digest, IdentityKind, TERRANE_V1},
    indexing::{IndexEvaluationRecipe, carrier::SemanticContext, evaluation},
    tree_builder::Tree,
    tree_format::{Attribute, Property, TreeUse},
};

const MINIMUM: u64 = 262144;
const INTERPRETER: &str = "/terrane-fixture/interpreter";

struct Script {
    body: Vec<u8>,
    value: AttributeValue,
    canonical: Vec<u8>,
    object: Digest,
}

fn script(limit: usize) -> TestResult<Script> {
    for length in 0..4096 {
        let argument = "a".repeat(length);
        let body = format!("#!{INTERPRETER} {argument}\n").into_bytes();
        let parsed = parse_shebang(&body, true)?;
        let mut canonical = Vec::new();
        cbor::write_map(&mut canonical, 2);
        cbor::write_uint(&mut canonical, 1);
        cbor::write_text(&mut canonical, INTERPRETER);
        cbor::write_uint(&mut canonical, 2);
        if argument.is_empty() {
            canonical.push(0xf6);
        } else {
            cbor::write_text(&mut canonical, &argument);
        }
        let value = AttributeValue::Shebang(parsed);
        assert_eq!(value.encode()?, canonical);
        let object = TERRANE_V1
            .calculate(IdentityKind::Chunk, &body)?
            .terrane_v1_digest()?;
        let mut key = canonical.clone();
        key.extend_from_slice(&object);
        if key.len() == limit {
            assert_eq!(classify_magic(&body), Magic::Shebang);
            return Ok(Script {
                body,
                value,
                canonical,
                object,
            });
        }
    }
    Err("no exact canonical shebang key length".into())
}

async fn producer(repository: &NativeRepository, script: &Script) -> TestResult<Vec<u8>> {
    let token = crate::ref_advance::tests::token();
    let mut session = repository.begin(REFERENCE, &token, "sdk").await?;
    let parents = session
        .record()
        .map(|record| vec![record.commit])
        .unwrap_or_default();
    let mut request = crate::ref_advance::tests::request_file(parents, &script.body);
    let evidence = TreeEvidence::load_tree(
        repository.coordinator().store(),
        request.commit.tree,
        &request.uploads,
        MINIMUM,
    )
    .await?;
    let prepared = PreparedTree::from_tree(&evidence.tree(evidence.root, MINIMUM)?)?;
    request.uploads.retain(|upload| {
        !matches!(
            upload,
            StagedUpload::Meta {
                kind: IdentityKind::Node,
                ..
            }
        )
    });
    let published = repository
        .commit_with_report(&mut session, prepared, request)
        .await?;
    let history = repository
        .coordinator()
        .guard()
        .verified_history(published.record.commit)
        .await?;
    let verified = history
        .commit(&published.record.commit)
        .ok_or_else(invalid)?;
    let mut record = AttrRecord::new(script.object, script.value.clone(), published.record.commit);
    record.sign(
        verified,
        &crate::ref_advance::tests::request(Vec::new()).terminal_secret,
    )?;
    let checked = repository
        .coordinator()
        .guard()
        .checked_attribute_record(record.clone(), &token, "sdk")
        .await?;
    assert_eq!(checked.producer.as_verified().value(), script.canonical);
    Ok(record.encode()?)
}

async fn candidate(
    repository: &NativeRepository,
    script: &Script,
    parents: Vec<Digest>,
    side: &[u8],
    binding: Option<Digest>,
) -> TestResult<(PreparedTree, CommitRequest)> {
    let mut request = crate::ref_advance::tests::request_file(parents, &script.body);
    let prepared = {
        let evidence = TreeEvidence::load_tree(
            repository.coordinator().store(),
            request.commit.tree,
            &request.uploads,
            MINIMUM,
        )
        .await?;
        let original = evidence.tree(evidence.root, MINIMUM)?;
        let magic = AttributeValue::Magic(Magic::Shebang).encode()?;
        let mut entries = original.iter().cloned().collect::<Vec<_>>();
        let first = entries.first_mut().ok_or_else(invalid)?;
        first.entry.attrs.extend([
            Attribute {
                name: "class.magic",
                value: &magic,
            },
            Attribute {
                name: "class.shebang",
                value: &script.canonical,
            },
        ]);
        first
            .entry
            .attrs
            .sort_by(|left, right| left.name.cmp(right.name));
        let mut names = Vec::new();
        cbor::write_array(&mut names, 1);
        cbor::write_text(&mut names, "class.shebang");
        let roots = binding.map(|root| {
            let mut bytes = Vec::new();
            cbor::write_map(&mut bytes, 2);
            cbor::write_text(&mut bytes, "value");
            cbor::write_map(&mut bytes, 1);
            cbor::write_text(&mut bytes, "class.shebang");
            cbor::write_text(
                &mut bytes,
                &root
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>(),
            );
            cbor::write_text(&mut bytes, "inherit");
            bytes.push(0xf4);
            bytes
        });
        let mut properties = original.props().unwrap_or_default().to_vec();
        properties.push(Property {
            name: "index",
            value: &names,
        });
        if let Some(roots) = &roots {
            properties.push(Property {
                name: "index-roots",
                value: roots,
            });
        }
        properties.sort_by(|left, right| {
            (left.name.len(), left.name).cmp(&(right.name.len(), right.name))
        });
        PreparedTree::from_tree(&Tree::build(
            entries,
            Some(properties),
            MINIMUM,
            TreeUse::Ordinary,
        )?)?
    };
    request.commit.tree = prepared.root();
    request.uploads.retain(|upload| {
        !matches!(
            upload,
            StagedUpload::Meta {
                kind: IdentityKind::Node,
                ..
            }
        )
    });
    request.uploads.push(StagedUpload::Meta {
        kind: IdentityKind::Attribute,
        bytes: side.to_vec(),
    });
    Ok((prepared, request))
}

/// Publishes the exact boundary value and refuses the valid oversized value.
///
/// # Errors
/// Preserves native factory, producer, strict-load and durable snapshot failures.
/// # Panics
/// Panics if typed refusals, canonical bytes or durable state disagree.
pub(super) async fn exercise() -> TestResult {
    let fixture = Fixture::new().await?;
    let repository = &fixture.repository;
    let accepted = script(4096)?;
    let oversized = script(4097)?;
    assert_ne!(accepted.object, oversized.object);
    let accepted_side = producer(repository, &accepted).await?;
    let oversized_side = producer(repository, &oversized).await?;

    let token = crate::ref_advance::tests::token();
    let mut session = repository.begin(REFERENCE, &token, "sdk").await?;
    let parent = session.record().ok_or_else(invalid)?.commit;
    let (tree, _) = candidate(repository, &accepted, vec![parent], &accepted_side, None).await?;
    let expected = {
        let source = tree.tree()?;
        evaluation::construct(
            &IndexEvaluationRecipe::new(tree.root(), "class.shebang")?,
            &BTreeMap::from([(tree.root(), source)]),
            MINIMUM,
            SemanticContext::new(3, 2, 1)?,
        )?
    };
    let (tree, mut request) = candidate(
        repository,
        &accepted,
        vec![parent],
        &accepted_side,
        Some(expected.root),
    )
    .await?;
    request.uploads.extend(
        expected
            .nodes
            .values()
            .cloned()
            .map(|bytes| StagedUpload::Meta {
                kind: IdentityKind::Node,
                bytes,
            }),
    );
    let report = repository
        .commit_with_report(&mut session, tree, request)
        .await?;
    assert_eq!(report.index_work.operations.len(), 1);
    assert_eq!(
        report.index_work.operations[0].association.index,
        expected.root
    );
    for (digest, bytes) in &expected.nodes {
        let identity = TERRANE_V1.from_digest(IdentityKind::Node, digest)?;
        assert_eq!(
            repository
                .coordinator()
                .store()
                .get(&identity, None)
                .await?,
            *bytes
        );
    }
    let reopened = fixture.reopen().await?;
    let loaded = indexing::load(
        reopened.coordinator().store(),
        report.index_work.operations[0].owner,
        "class.shebang",
        SemanticRevisions {
            property: 3,
            attribute: 2,
            tree: 1,
        },
        MINIMUM,
    )
    .await?;
    let sources = loaded.sources()?;
    let strict = loaded.prepare(&sources.trees)?;
    assert_eq!(strict.root(), expected.root);
    assert!(strict.all_missing()?.rows.is_empty());
    assert!(strict.gap_root().is_none());

    let mut session = repository.begin(REFERENCE, &token, "sdk").await?;
    let (tree, request) = candidate(
        repository,
        &oversized,
        vec![report.record.commit],
        &oversized_side,
        Some(expected.root),
    )
    .await?;
    let mut prospective = Vec::new();
    for upload in request.uploads.iter().chain(tree.uploads.iter()) {
        let identity = match upload {
            StagedUpload::Chunk { identity, .. } => identity.clone(),
            StagedUpload::Meta { kind, bytes } => TERRANE_V1.calculate(*kind, bytes)?,
        };
        prospective.push(identity);
    }
    let presence = repository.coordinator().store().has(&prospective).await?;
    let reference = repository.coordinator().store().ref_get(REFERENCE).await?;
    let lineage = repository
        .coordinator()
        .store()
        .ref_log_read(REFERENCE, 1)
        .await?;
    let catalog = repository
        .coordinator()
        .store()
        .attribute_identities()
        .await?;
    let originals = repository
        .coordinator()
        .guard()
        .original_commits
        .read()
        .map_err(|_| invalid())?
        .clone();
    let physical = image(repository.coordinator().store().root()).await?;
    let mut controls = image(&fixture.control).await?;
    let baseline = originals
        .values()
        .find(|context| context.commit() == &report.record.commit)
        .ok_or_else(invalid)?
        .baseline();
    let mut baseline_bytes = Vec::new();
    cbor::write_array(&mut baseline_bytes, 5);
    cbor::write_uint(&mut baseline_bytes, 1);
    cbor::write_bytes(&mut baseline_bytes, baseline.authority().id());
    cbor::write_text(&mut baseline_bytes, session.reference());
    cbor::write_uint(&mut baseline_bytes, session.epoch());
    cbor::write_array(&mut baseline_bytes, baseline.acl().len());
    for (subject, verbs) in baseline.acl() {
        cbor::write_array(&mut baseline_bytes, 2);
        cbor::write_text(&mut baseline_bytes, subject);
        cbor::write_uint(&mut baseline_bytes, u64::from(*verbs));
    }
    let hexadecimal = |bytes: &[u8]| {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let baseline_key = PathBuf::from(format!(
        "bootstrap-{}-{}-{}.cbor",
        hexadecimal(baseline.authority().id()),
        hexadecimal(blake3::hash(session.reference().as_bytes()).as_bytes()),
        session.epoch(),
    ));
    // Repository retains the exact epoch baseline before admission. It creates no
    // candidate association, immutable publication, selected ref or lineage effect.
    assert!(controls.insert(baseline_key, baseline_bytes).is_none());
    let publication = publication_image(repository).await?;

    let error = match repository
        .commit_with_report(&mut session, tree, request)
        .await
    {
        Err(crate::repository::Error::Advance(crate::ref_advance::AdvanceError::Store(error)))
        | Err(crate::repository::Error::Store(error)) => error,
        other => panic!("expected native key-limit refusal, got {other:?}"),
    };
    assert_eq!(error.kind(), invalid().kind());
    assert_eq!(
        error
            .source()
            .and_then(|cause| cause.downcast_ref::<terrane_format::indexing::Error>()),
        Some(&terrane_format::indexing::Error::Limit)
    );
    assert_eq!(
        repository.coordinator().store().ref_get(REFERENCE).await?,
        reference
    );
    assert_eq!(
        repository
            .coordinator()
            .store()
            .ref_log_read(REFERENCE, 1)
            .await?,
        lineage
    );
    assert_eq!(
        repository
            .coordinator()
            .store()
            .attribute_identities()
            .await?,
        catalog
    );
    assert_eq!(
        *repository
            .coordinator()
            .guard()
            .original_commits
            .read()
            .map_err(|_| invalid())?,
        originals
    );
    assert_eq!(
        repository.coordinator().store().has(&prospective).await?,
        presence
    );
    assert_eq!(
        image(repository.coordinator().store().root()).await?,
        physical
    );
    assert_eq!(image(&fixture.control).await?, controls);
    assert_eq!(publication_image(repository).await?, publication);
    Ok(())
}

async fn image(root: &Path) -> TestResult<BTreeMap<PathBuf, Vec<u8>>> {
    let mut pending = vec![root.to_path_buf()];
    let mut result = BTreeMap::new();
    while let Some(path) = pending.pop() {
        let relative = path.strip_prefix(root)?;
        // Locks and live leases are session coordination, not durable publication data.
        if relative.components().any(|component| {
            matches!(
                component.as_os_str().to_str(),
                Some(".terrane-locks" | "leases")
            )
        }) {
            continue;
        }
        let metadata = TokioLocalFs.symlink_metadata(&path).await?;
        if metadata.is_dir() {
            pending.extend(TokioLocalFs.read_dir(&path).await?);
        } else if metadata.is_file() {
            result.insert(
                relative.to_path_buf(),
                TokioLocalFs.read_nofollow(&path).await?,
            );
        } else {
            return Err("unexpected non-file publication artifact".into());
        }
    }
    Ok(result)
}

async fn publication_image(
    repository: &NativeRepository,
) -> TestResult<BTreeMap<PathBuf, Option<Vec<u8>>>> {
    let holder =
        crate::bucket::held::SingleHeld::acquire_read_only(repository.coordinator().store())
            .await?;
    let held = holder.source();
    let observed = held.observe_publication_unrepaired().await?;
    Ok(observed
        .physical_reads()
        .iter()
        .map(|read| {
            (
                read.path().to_path_buf(),
                read.bytes().map(ToOwned::to_owned),
            )
        })
        .collect())
}
