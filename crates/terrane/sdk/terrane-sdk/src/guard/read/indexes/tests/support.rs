//! Builds genuine active-profile repositories and independent finite Index bytes.

use std::collections::BTreeMap;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::time::Duration;

use crate::bucket::{FileBucket, FileBucketConfig, FileBucketPublicationConfig};
use crate::domain::DomainNamespace;
use crate::guard::{
    AuthoringNamespaceProfile, AuthorizedSnapshot, Guard, HistoryObservation,
    RecordedNamespaceProfile, RecordedNamespaceProfiles, StagedUpload, TreeEvidence, invalid,
};
use crate::ref_advance::{CommitTiming, Coordinator};
use crate::repository::{CommitReport, PreparedTree, Repository};
use crate::store::{ContentValidator, LocalFs, MetaUpload, StoreFailure, TokioClock};
use terrane_format::cbor;
use terrane_format::derived::{AttributeValue, PlaintextHashes};
use terrane_format::identity::{Digest, IdentityKind, TERRANE_V1};
use terrane_format::properties::semantics::associations::RecordedAssociation;
use terrane_format::refs::Commit;
use terrane_format::tree_builder::Tree;
use terrane_format::tree_format::{self, Attribute, Property, TreeUse};

use super::current::ObservedFs;

/// Uses the ordinary signed writer reference for live lookup policy.
pub(super) const REFERENCE: &str = "refs/heads/_/main";

/// Keeps a known literal SHA-256 independent of the index encoder.
pub(super) const BODY: &[u8] = b"hello";

/// Selects the registered value name through actual authoring configuration.
pub(super) const ATTRIBUTE: &str = "hash.sha256";

/// Names the genuine wrapped native repository used for read handoffs.
pub(super) type NativeRepository =
    Repository<FileBucket<ObservedFs, TokioClock, Validator>, TokioClock, ObservedFs>;

/// Preserves storage/setup causes instead of accepting arbitrary fixture refusal.
pub(super) type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Validates each actual metadata role with its existing canonical codec.
#[derive(Clone)]
pub(super) struct Validator;

impl ContentValidator for Validator {
    fn validate_meta(&self, upload: &MetaUpload<'_>) -> Result<(), StoreFailure> {
        let valid = match upload.kind() {
            IdentityKind::Node => [TreeUse::Ordinary, TreeUse::Index].into_iter().any(|role| {
                tree_format::decode_node_for(upload.bytes(), true, 262144, role).is_ok()
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

/// Retains actual independently configured native factory inputs for supported reopen.
pub(super) struct Fixture {
    /// Actual initialized repository, including protected Original contexts.
    pub(super) repository: NativeRepository,
    /// Genuine same-Arc wrapper around the actual Tokio native executor.
    pub(super) fs: ObservedFs,
    /// Actual private administrative directory initialized by the factory.
    pub(super) control: std::path::PathBuf,
    /// Original configuration used for ordinary same-profile reopen.
    pub(super) bucket_config: FileBucketConfig,
    /// Independent semantic inputs retained before the native factory signs any view.
    pub(super) authoring: AuthoringNamespaceProfile,
    /// Actual configured physical operator verified by initialization.
    pub(super) owner: u32,
}

impl Fixture {
    /// Initializes profile2 before signing or durable selected Guard creation.
    ///
    /// # Errors
    /// Preserves native factory, entropy, initialization and protected retention failures.
    /// # Panics
    /// Propagates assertions in the genuine shared seed fixture.
    pub(super) async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let seed = crate::ref_advance::tests::fixture().await;
        let fs = ObservedFs::default();
        let entropy = fs.random_bytes(16).await?;
        let suffix = entropy
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let root = std::env::temp_dir().join(format!("terrane-index-lookup-{suffix}"));
        let control = root.with_file_name(format!("terrane-index-lookup-{suffix}-original"));
        fs.create_dir_new(&control).await?;
        fs.set_permissions_and_sync(&control, std::fs::Permissions::from_mode(0o700))
            .await?;
        let owner = fs.symlink_metadata(&control).await?.uid();
        let config = seed.guard().config().clone();
        let bucket_config = FileBucketConfig {
            root: root.clone(),
            publication_control: Some(FileBucketPublicationConfig {
                operator_uid: owner,
                control: None,
            }),
            chunk_profile_name: config.chunk_profile_name.clone(),
            chunk_profile: (*config.chunk_profile).clone(),
            locality: config.home.clone(),
        };
        let bucket =
            FileBucket::open(bucket_config.clone(), fs.clone(), TokioClock, Validator).await?;
        let authoring = AuthoringNamespaceProfile::new(3, 3, &[], 2)?;
        let guard = Guard::new_active(bucket, TokioClock, seed.guard().keys().to_vec(), config)
            .with_recorded_authoring(
                authoring.clone().context().clone(),
                authoring.clone().registries().attribute_revision,
            )?;
        let repository = Repository::initialize_native_retention(
            Coordinator::new(guard, timing()?, fs.clone()),
            &DomainNamespace {
                root,
                domain: "public".into(),
            },
            &control,
            owner,
        )
        .await?;
        Ok(Self {
            repository,
            fs,
            control,
            bucket_config,
            authoring,
            owner,
        })
    }

    /// Reopens the same real profile and independently reloads protected Originals.
    ///
    /// # Errors
    /// Preserves ordinary open, profile, registration and full native reload failures.
    /// Refuses a genuinely Legacy factory row instead of relabeling it Recorded.
    ///
    /// # Panics
    /// Panics if a completed factory view differs from its originally installed inputs.
    pub(super) async fn reopen(&self) -> Result<NativeRepository, Box<dyn std::error::Error>> {
        let old = self.repository.coordinator().guard();
        // The actual Original observations enumerate this fixture's completed producer views only. The
        // trusted semantic inputs remain the object installed before initialization;
        // neither completed output nor serialized D110 context selects a revision.
        let mut views = std::collections::BTreeSet::new();
        // Include all installed Originals so a genuinely Legacy dependency is
        // detected explicitly, rather than omitted from a Recorded-only table.
        views.extend(
            old.original_commits
                .read()
                .map_err(|_| invalid())?
                .keys()
                .copied(),
        );
        let inputs = self.authoring.registries();
        let context = self.authoring.context().clone();
        let mut profiles = Vec::new();
        for view in views {
            let (verified, history) = old
                .verified_tree_history_observed(view, HistoryObservation::default())
                .await?;
            assert!(history.commit(&view).is_some());
            let association =
                RecordedAssociation::new(view, verified.commit.commit().tree, context.clone());
            let (selected, actual_inputs) =
                old.selected_view_profile(&verified.commit, HistoryObservation::default())?;
            match selected {
                crate::guard::recorded_properties::SelectedReadInterpretation::Recorded(actual) => {
                    assert_eq!(actual.as_ref(), &association);
                    assert_eq!(&actual_inputs, inputs);
                }
                crate::guard::recorded_properties::SelectedReadInterpretation::Legacy => {
                    // A strict Recorded table cannot express a Legacy factory row.
                    // Refuse rather than silently reinterpret a bootstrap view.
                    return Err(crate::store::StoreFailure::new(
                        crate::store::StoreErrorKind::Unsupported,
                    )
                    .into());
                }
            }
            profiles.push(RecordedNamespaceProfile::new(
                association,
                inputs.attribute_revision,
            )?);
        }
        let profiles = RecordedNamespaceProfiles::new(profiles)?;
        let bucket = FileBucket::open(
            self.bucket_config.clone(),
            self.fs.clone(),
            TokioClock,
            Validator,
        )
        .await?;
        let guard = Guard::new_active(
            bucket,
            TokioClock,
            old.keys().to_vec(),
            old.config().clone(),
        )
        .with_recorded_authoring(
            self.authoring.clone().context().clone(),
            self.authoring.clone().registries().attribute_revision,
        )?
        .with_recorded_namespace_profiles(profiles)?;
        Ok(Repository::reopen_native_retention(
            Coordinator::new(guard, timing()?, self.fs.clone()),
            &DomainNamespace {
                root: self.bucket_config.root.clone(),
                domain: "public".into(),
            },
            &self.control,
            self.owner,
        )
        .await?)
    }
}

fn timing() -> Result<CommitTiming, crate::ref_advance::AdvanceError> {
    CommitTiming::new(
        Duration::from_secs(30),
        Duration::from_secs(60),
        Duration::from_secs(10),
    )
}

/// Encodes a real complete plaintext hash and verifies a separate fixed oracle.
///
/// # Errors
/// Preserves registered complete-plaintext hashing and canonical value errors.
/// # Panics
/// Panics if the independent literal hash differs from the actual complete plaintext.
pub(super) fn value() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut hashes = PlaintextHashes::new(BODY.len() as u64);
    hashes.update(BODY)?;
    let digest = hashes.finish()?.sha256;
    assert_eq!(
        hex(digest),
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    );
    Ok(AttributeValue::Sha256(digest).encode()?)
}

/// Predicts the actual Chunk identity using the registered content address domain.
///
/// # Errors
/// Preserves canonical identity profile errors.
pub(super) fn object() -> Result<Digest, Box<dyn std::error::Error>> {
    Ok(TERRANE_V1
        .calculate(IdentityKind::Chunk, BODY)?
        .terrane_v1_digest()?)
}

/// Builds and publishes a genuine finite namespace through the unchanged writer pipeline.
///
/// `present` and `missing` are canonical local file keys with identical actual
/// plaintext. Initial missing attributes are authored without requirements;
/// adding requirements later retains those entries as honest backfill gaps.
///
/// # Errors
/// Preserves native signing/admission, namespace and durable publication failures.
/// # Panics
/// Propagates the actual shared token/request construction and literal hash assertions.
pub(super) async fn publish(
    repository: &NativeRepository,
    present: &[&[u8]],
    missing: &[&[u8]],
    required: bool,
    bound: bool,
) -> Result<CommitReport, Box<dyn std::error::Error>> {
    publish_policy(
        repository,
        present,
        missing,
        required,
        bound,
        Some(31),
        None,
    )
    .await
}

/// Publishes actual independently chosen ACL/trust policy through native admission.
///
/// `verbs=None` publishes an explicitly empty canonical ACL. Every nonempty
/// verb set retains the registered AUTH-22 implication rules.
///
/// # Errors
/// Preserves signed namespace/admission, Original and durable publication failures.
/// # Panics
/// Propagates actual shared token/request construction and independent hash assertions.
pub(super) async fn publish_policy(
    repository: &NativeRepository,
    present: &[&[u8]],
    missing: &[&[u8]],
    required: bool,
    bound: bool,
    verbs: Option<u8>,
    trust: Option<&[u8]>,
) -> Result<CommitReport, Box<dyn std::error::Error>> {
    let token = crate::ref_advance::tests::token();
    let mut session = repository.begin(REFERENCE, &token, "sdk").await?;
    let parents = session
        .record()
        .map(|record| vec![record.commit])
        .unwrap_or_default();
    let mut request =
        crate::ref_advance::tests::request_file_acl(parents, BODY, verbs.unwrap_or(31));
    let guard = repository.coordinator().guard();
    let evidence =
        TreeEvidence::load_tree(guard.store(), request.commit.tree, &request.uploads, 262144)
            .await?;
    let original = evidence.tree(evidence.root, 262144)?;
    let model = original.iter().next().ok_or_else(invalid)?;
    let value = value()?;
    let mut entries = Vec::new();
    for key in present {
        let mut entry = model.entry.clone();
        entry.attrs.push(Attribute {
            name: ATTRIBUTE,
            value: &value,
        });
        entry.attrs.sort_by(|a, b| a.name.cmp(b.name));
        entries.push(terrane_format::tree_format::LeafItem {
            key: key.to_vec(),
            entry,
        });
    }
    for key in missing {
        entries.push(terrane_format::tree_format::LeafItem {
            key: key.to_vec(),
            entry: model.entry.clone(),
        });
    }
    entries.sort_by(|a, b| a.key.cmp(&b.key));
    let required_names = if required {
        names(&[ATTRIBUTE])
    } else {
        names(&[])
    };
    // Missing Index values are lawful preexisting gaps. A separate hashes
    // requirement would reject those newly added entries under PROP-18/21.
    let hashes = names(&[]);
    let (primary, nodes) = expected(present, missing, &value)?;
    let roots = bound.then(|| binding(primary));
    let mut properties = original.props().unwrap_or_default().to_vec();
    if verbs.is_none() {
        // AUTH-22 makes Admin imply Read. A genuine empty ACL removes the
        // principal instead of pretending that removing the raw Read bit revokes it.
        properties.retain(|property| property.name != "acl");
        properties.push(Property {
            name: "acl",
            value: b"\x80",
        });
    }

    if let Some(trust) = trust {
        properties.push(Property {
            name: "trust",
            value: trust,
        });
    }
    properties.push(Property {
        name: "index",
        value: &required_names,
    });
    properties.push(Property {
        name: "hashes",
        value: &hashes,
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
    if bound {
        request
            .uploads
            .extend(nodes.values().map(|bytes| StagedUpload::Meta {
                kind: IdentityKind::Node,
                bytes: bytes.clone(),
            }));
    }
    Ok(repository
        .commit_with_report(&mut session, prepared, request)
        .await?)
}

/// Gets a real ordinary current-authorized snapshot under the actual factory Guard.
///
/// # Errors
/// Preserves current policy, Original, trust, signature and metadata failures.
/// # Panics
/// Propagates genuine shared token construction assertions.
pub(super) async fn snapshot(
    repository: &NativeRepository,
) -> Result<AuthorizedSnapshot, StoreFailure> {
    repository
        .coordinator()
        .guard()
        .read_snapshot(REFERENCE, &crate::ref_advance::tests::token(), b"/", "sdk")
        .await
}

fn names(values: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    cbor::write_array(&mut out, values.len());
    for value in values {
        cbor::write_text(&mut out, value);
    }
    out
}

fn hex(digest: Digest) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn binding(index: Digest) -> Vec<u8> {
    let mut out = b"\xa2\x65value\xa1\x6bhash.sha256".to_vec();
    cbor::write_text(&mut out, &hex(index));
    out.extend_from_slice(b"\x67inherit\xf4");
    out
}

/// Bundles the independently encoded primary identity and auxiliary Node bodies.
type ExpectedIndex = (Digest, BTreeMap<Digest, Vec<u8>>);

/// Independently encodes the complete finite primary, gap and local route records.
///
/// # Errors
/// Preserves typed content and auxiliary Node identity construction errors.
pub(super) fn expected(
    present: &[&[u8]],
    missing: &[&[u8]],
    value: &[u8],
) -> Result<ExpectedIndex, Box<dyn std::error::Error>> {
    let object = object()?;
    let mut nodes = BTreeMap::new();
    let mut forward = |keys: &[&[u8]]| -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let terminal = carrier(object, None);
        let route = insert(
            &mut nodes,
            leaf(
                &keys
                    .iter()
                    .map(|key| (key.to_vec(), terminal.clone()))
                    .collect::<Vec<_>>(),
                None,
            ),
        )?;
        Ok(carrier(object, Some(route)))
    };
    let mut primary = Vec::new();
    if !present.is_empty() {
        let mut key = value.to_vec();
        key.extend(object);
        primary.push((key, forward(present)?));
    }
    let gap_rows = if missing.is_empty() {
        Vec::new()
    } else {
        vec![(object.to_vec(), forward(missing)?)]
    };
    let gap = if gap_rows.is_empty() {
        None
    } else {
        Some(insert(&mut nodes, leaf(&gap_rows, None))?)
    };
    let props = gap.map(|gap| {
        let mut out = b"\xa1\x6aindex-gaps\xa2\x65value".to_vec();
        cbor::write_text(&mut out, &hex(gap));
        out.extend_from_slice(b"\x67inherit\xf4");
        out
    });
    let primary = insert(&mut nodes, leaf(&primary, props.as_deref()))?;
    Ok((primary, nodes))
}

fn carrier(object: Digest, route: Option<Digest>) -> Vec<u8> {
    let mut out = vec![if route.is_some() { 0xa3 } else { 0xa2 }, 1, 7];
    if let Some(route) = route {
        out.extend_from_slice(b"\x09\xa1\x71index.occurrences");
        cbor::write_bytes(&mut out, &route);
    }
    out.extend_from_slice(&[14, 0x81]);
    cbor::write_bytes(&mut out, &object);
    out
}

fn leaf(rows: &[(Vec<u8>, Vec<u8>)], properties: Option<&[u8]>) -> Vec<u8> {
    let mut out = vec![if properties.is_some() { 0xa3 } else { 0xa2 }, 1, 0, 2];
    cbor::write_array(&mut out, rows.len());
    let mut previous: &[u8] = &[];
    for (key, entry) in rows {
        let shared = key.iter().zip(previous).take_while(|(a, b)| a == b).count();
        out.push(0x83);
        cbor::write_bytes(&mut out, &key[shared..]);
        cbor::write_uint(&mut out, shared as u64);
        out.extend_from_slice(entry);
        previous = key;
    }
    if let Some(properties) = properties {
        out.push(3);
        out.extend_from_slice(properties);
    }
    out
}

fn insert(
    nodes: &mut BTreeMap<Digest, Vec<u8>>,
    bytes: Vec<u8>,
) -> Result<Digest, Box<dyn std::error::Error>> {
    let digest = TERRANE_V1
        .calculate(IdentityKind::Node, &bytes)?
        .terrane_v1_digest()?;
    nodes.insert(digest, bytes);
    Ok(digest)
}
