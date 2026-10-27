//! Builds real retained native repositories and finite independent I/P/G bytes.

use std::collections::BTreeMap;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::time::Duration;

use crate::bucket::{FileBucket, FileBucketConfig, FileBucketPublicationConfig};
use crate::domain::DomainNamespace;
use crate::guard::{
    AuthoringNamespaceProfile, CommitRequest, Guard, StagedUpload, TreeEvidence, invalid,
};
use crate::ref_advance::{CommitTiming, Coordinator};
use crate::repository::{CommitReport, PreparedTree, Repository};
use crate::store::{ContentValidator, LocalFs, MetaUpload, StoreFailure, TokioClock, TokioLocalFs};
use terrane_format::{
    cbor,
    identity::{Digest, IdentityKind, TERRANE_V1},
    refs::Commit,
    tree_builder::Tree,
    tree_format::{self, Attribute, Property, TreeUse},
};

/// Selects the genuine shared writer reference.
pub(super) const REFERENCE: &str = "refs/heads/_/main";

/// Uses real admitted Chunk bytes, independent of the auxiliary index records.
pub(super) const BODY: &[u8] = b"required-index immutable body";

/// Names the genuine native bucket used by these publication cases.
pub(super) type Bucket = FileBucket<TokioLocalFs, TokioClock, Validator>;

/// Names a Repository retaining actual native Original controls.
pub(super) type NativeRepository = Repository<Bucket, TokioClock, TokioLocalFs>;

/// Names the independently predicted primary identity and complete auxiliary bytes.
pub(super) type ExpectedIndex = (Digest, BTreeMap<Digest, Vec<u8>>);

/// Validates canonical ordinary and contextual auxiliary metadata with pure codecs.
#[derive(Clone)]
pub(super) struct Validator;

impl ContentValidator for Validator {
    fn validate_meta(&self, upload: &MetaUpload<'_>) -> Result<(), StoreFailure> {
        let valid = match upload.kind() {
            IdentityKind::Node => [TreeUse::Ordinary, TreeUse::Index]
                .into_iter()
                .any(|usage| {
                    tree_format::decode_node_for(upload.bytes(), true, 262144, usage).is_ok()
                }),
            IdentityKind::Commit => Commit::decode(upload.bytes()).is_ok(),
            IdentityKind::Attribute => {
                terrane_format::derived::AttrRecord::decode(upload.bytes()).is_ok()
            }
            _ => false,
        };
        if valid { Ok(()) } else { Err(invalid()) }
    }
}

/// Initializes a fresh real native authority with independently installed authoring inputs.
///
/// # Errors
/// Preserves native entropy, storage, registration, profile and retention failures.
/// # Panics
/// Propagates genuine shared seed fixture setup assertions.
pub(super) async fn repository(
    attribute: u64,
) -> Result<NativeRepository, Box<dyn std::error::Error>> {
    let seed = crate::ref_advance::tests::fixture().await;
    let entropy = TokioLocalFs.random_bytes(16).await?;
    let suffix = entropy
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let root = std::env::temp_dir().join(format!("terrane-index-writer-{suffix}"));
    let control = root.with_file_name(format!("terrane-index-writer-{suffix}-original"));
    TokioLocalFs.create_dir_new(&control).await?;
    TokioLocalFs
        .set_permissions_and_sync(&control, std::fs::Permissions::from_mode(0o700))
        .await?;
    let owner = TokioLocalFs.symlink_metadata(&control).await?.uid();
    let config = seed.guard().config().clone();
    let bucket = FileBucket::open(
        FileBucketConfig {
            root: root.clone(),
            publication_control: Some(FileBucketPublicationConfig {
                operator_uid: owner,
                control: None,
            }),
            chunk_profile_name: config.chunk_profile_name.clone(),
            chunk_profile: (*config.chunk_profile).clone(),
            locality: config.home.clone(),
        },
        TokioLocalFs,
        TokioClock,
        Validator,
    )
    .await?;
    let guard = Guard::new_with_authoring_namespace_profile(
        bucket,
        TokioClock,
        seed.guard().keys().to_vec(),
        config,
        AuthoringNamespaceProfile::new(3, 3, &[], attribute)?,
    );
    Ok(Repository::initialize_native_retention(
        Coordinator::new(
            guard,
            CommitTiming::new(
                Duration::from_secs(30),
                Duration::from_secs(60),
                Duration::from_secs(10),
            )?,
            TokioLocalFs,
        ),
        &DomainNamespace {
            root,
            domain: "public".into(),
        },
        &control,
        owner,
    )
    .await?)
}

/// Builds an ordinary unsigned candidate with exact required policy and local binding.
///
/// # Errors
/// Preserves canonical namespace, address and staging failures.
/// # Panics
/// Propagates shared unsigned request construction assertions.
pub(super) async fn request(
    repository: &NativeRepository,
    parents: Vec<Digest>,
    value: Option<u64>,
    required: bool,
    binding: Option<Digest>,
    extra: &BTreeMap<Digest, Vec<u8>>,
) -> Result<(PreparedTree, CommitRequest), Box<dyn std::error::Error>> {
    let mut request = crate::ref_advance::tests::request_file(parents, BODY);
    let guard = repository.coordinator().guard();
    let evidence =
        TreeEvidence::load_tree(guard.store(), request.commit.tree, &request.uploads, 262144)
            .await?;
    let original = evidence.tree(evidence.root, 262144)?;
    let mut encoded_value = Vec::new();
    let mut entries = original.iter().cloned().collect::<Vec<_>>();
    if let Some(value) = value {
        cbor::write_uint(&mut encoded_value, value);
    }
    if let Some(first) = entries.first_mut() {
        if value.is_some() {
            first.entry.attrs.push(Attribute {
                name: "uid",
                value: &encoded_value,
            });
        }
        first.entry.attrs.sort_by(|a, b| a.name.cmp(b.name));
    }
    let names = if required {
        vec![0x81, 0x63, b'u', b'i', b'd']
    } else {
        vec![0x80]
    };
    let roots = binding.map(|identity| wrapper(map(vec![("uid", text(&hex(identity)))])));
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
    properties.sort_by(|a, b| (a.name.len(), a.name).cmp(&(b.name.len(), b.name)));
    let tree = Tree::build(entries, Some(properties), 262144, TreeUse::Ordinary)?;
    let prepared = PreparedTree::from_tree(&tree)?;
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
    request
        .uploads
        .extend(extra.values().map(|bytes| StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes: bytes.clone(),
        }));
    Ok((prepared, request))
}

/// Publishes through the public report-returning pipeline with genuine prepared data.
///
/// # Errors
/// Preserves ordinary session, normalization, admission and durable publication failures.
/// # Panics
/// Propagates shared request and token fixture setup assertions.
pub(super) async fn publish(
    repository: &NativeRepository,
    value: Option<u64>,
    required: bool,
    binding: Option<Digest>,
    extra: &BTreeMap<Digest, Vec<u8>>,
) -> Result<CommitReport, Box<dyn std::error::Error>> {
    let token = crate::ref_advance::tests::token();
    let mut session = repository.begin(REFERENCE, &token, "sdk").await?;
    let parents = session
        .record()
        .map(|record| vec![record.commit])
        .unwrap_or_default();
    let (tree, request) = request(repository, parents, value, required, binding, extra).await?;
    Ok(repository
        .commit_with_report(&mut session, tree, request)
        .await?)
}

/// Predicts the entire one-file primary, gap and route closure from literal CBOR.
///
/// # Errors
/// Preserves immutable identity calculation errors.
pub(super) fn expected(value: Option<u64>) -> Result<ExpectedIndex, Box<dyn std::error::Error>> {
    let object = TERRANE_V1
        .calculate(IdentityKind::Chunk, BODY)?
        .terrane_v1_digest()?;
    let mut nodes = BTreeMap::new();
    let mut terminal = vec![0xa2, 1, 7, 14, 0x81];
    cbor::write_bytes(&mut terminal, &object);
    let route = insert(&mut nodes, leaf(&[(b"file".to_vec(), terminal)], None))?;
    let mut forward = vec![0xa3, 1, 7, 9, 0xa1];
    cbor::write_text(&mut forward, "index.occurrences");
    cbor::write_bytes(&mut forward, &route);
    forward.extend_from_slice(&[14, 0x81]);
    cbor::write_bytes(&mut forward, &object);
    let gap_rows = if value.is_none() {
        vec![(object.to_vec(), forward.clone())]
    } else {
        Vec::new()
    };
    let gap = if value.is_none() {
        Some(insert(&mut nodes, leaf(&gap_rows, None))?)
    } else {
        None
    };
    let rows = if let Some(value) = value {
        let mut key = Vec::new();
        cbor::write_uint(&mut key, value);
        key.extend_from_slice(&object);
        vec![(key, forward)]
    } else {
        Vec::new()
    };
    let properties = gap.map(|gap| map(vec![("index-gaps", wrapper(text(&hex(gap))))]));
    let primary = insert(&mut nodes, leaf(&rows, properties))?;
    Ok((primary, nodes))
}

fn insert(
    nodes: &mut BTreeMap<Digest, Vec<u8>>,
    bytes: Vec<u8>,
) -> Result<Digest, Box<dyn std::error::Error>> {
    let identity = TERRANE_V1
        .calculate(IdentityKind::Node, &bytes)?
        .terrane_v1_digest()?;
    nodes.insert(identity, bytes);
    Ok(identity)
}

fn leaf(rows: &[(Vec<u8>, Vec<u8>)], props: Option<Vec<u8>>) -> Vec<u8> {
    let mut out = vec![if props.is_some() { 0xa3 } else { 0xa2 }, 1, 0, 2];
    cbor::write_array(&mut out, rows.len());
    let mut previous: &[u8] = &[];
    for (key, entry) in rows {
        let shared = key.iter().zip(previous).take_while(|(a, b)| a == b).count();
        out.push(0x83);
        cbor::write_bytes(&mut out, &key[shared..]);
        cbor::write_uint(&mut out, shared as u64);
        out.extend(entry);
        previous = key;
    }
    if let Some(props) = props {
        out.push(3);
        out.extend(props);
    }
    out
}

fn map(mut entries: Vec<(&str, Vec<u8>)>) -> Vec<u8> {
    entries.sort_by(|(a, _), (b, _)| (a.len(), *a).cmp(&(b.len(), *b)));
    let mut out = Vec::new();
    cbor::write_map(&mut out, entries.len());
    for (name, value) in entries {
        cbor::write_text(&mut out, name);
        out.extend(value);
    }
    out
}

fn text(value: &str) -> Vec<u8> {
    let mut out = Vec::new();
    cbor::write_text(&mut out, value);
    out
}

fn wrapper(value: Vec<u8>) -> Vec<u8> {
    map(vec![("inherit", vec![0xf4]), ("value", value)])
}

fn hex(identity: Digest) -> String {
    identity.iter().map(|byte| format!("{byte:02x}")).collect()
}
