//! Builds real native repositories and independently constructed indexed namespaces.

use super::*;
use crate::domain::DomainNamespace;
use crate::guard::{Guard, GuardConfig, StagedUpload};
use crate::ref_advance::{CommitRequest, CommitTiming, Coordinator};
use crate::repository::{MetadataValidator, Repository};
use crate::store::{LocalFs, TokioClock, TokioLocalFs};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use terrane_core::indexing::{
    IndexEvaluationRecipe, IndexRoots, carrier::SemanticContext, evaluation,
};
use terrane_core::tree_builder::Tree;
use terrane_core::tree_format::{
    Attribute, ContentRef, Entry, EntryKind, LeafItem, Property, TreeUse,
};

/// Retains the real metadata validator and canonical local repository factories.
pub(super) type Native = Repository<
    crate::bucket::FileBucket<TokioLocalFs, TokioClock, MetadataValidator>,
    TokioClock,
    TokioLocalFs,
>;

/// Opens a fresh native namespace with an explicit genuine Guard selection.
///
/// # Errors
/// Preserves native backend, retention initialization and registered setup failures.
///
/// # Panics
/// Panics if the existing test configuration cannot prepare its real administrator records.
pub(super) async fn fixture(active: bool) -> Result<Native> {
    let nonce = TokioLocalFs.random_bytes(16).await?;
    let suffix = nonce
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let root = std::env::temp_dir().join(format!("terrane-active-completion-{suffix}"));
    let configuration = super::super::tests::config(root.clone()).await;
    let profile = configuration.chunk_profile.clone();
    let store = crate::bucket::FileBucket::open(
        configuration,
        TokioLocalFs,
        TokioClock,
        MetadataValidator::new(profile),
    )
    .await?;
    let keys = vec![terrane_core::auth::IssuerKey {
        issuer: "test".into(),
        key_id: "key".into(),
        public_key: terrane_core::auth::public_key_from_secret(&super::super::tests::secret()),
        retirement: None,
    }];
    let config = GuardConfig {
        store_name: "local".into(),
        private_domain: "private:test".into(),
        home: terrane_core::refs::Locality::default(),
        initial_acl: vec![("writer".into(), 31)],
        min_chunk_size: 262144,
        storage_domain: "public".into(),
        chunk_profile_name: "cdc-1m".into(),
        chunk_profile: Box::new(terrane_core::chunking::ChunkProfile::cdc_1m([0; 32])),
        policy_authority: None,
    };
    let guard = if active {
        Guard::new_active(store, TokioClock, keys, config)
    } else {
        Guard::new(store, TokioClock, keys, config)
    };
    let timing = CommitTiming::new(
        std::time::Duration::from_secs(30),
        std::time::Duration::from_secs(60),
        std::time::Duration::from_secs(10),
    )?;
    let coordinator = Coordinator::new(guard, timing, TokioLocalFs);
    let control = root.with_file_name(format!("terrane-active-original-{suffix}"));
    TokioLocalFs.create_dir_new(&control).await?;
    TokioLocalFs
        .set_permissions_and_sync(&control, std::fs::Permissions::from_mode(0o700))
        .await?;
    let owner = TokioLocalFs.symlink_metadata(&root).await?.uid();
    let namespace = DomainNamespace {
        root,
        domain: "public".into(),
    };
    Ok(Repository::initialize_native_retention(coordinator, &namespace, &control, owner).await?)
}

/// Owns real namespace uploads and independently constructed auxiliary bytes.
pub(super) struct Indexed {
    /// Carries the actual signed authoring request and immutable uploads.
    pub request: CommitRequest,
    /// Names the independently constructed namespace root.
    pub owner: Digest,
    /// Names its actual uid primary index root.
    pub primary: Digest,
    /// Retains canonical address-checked auxiliary Node bodies.
    pub index_nodes: std::collections::BTreeMap<Digest, Vec<u8>>,
}

/// Constructs an indexed namespace and real immutable uploads.
///
/// # Errors
/// Preserves physical tree, chunk identity, binding and evaluation failures.
///
/// # Panics
/// Panics if the independent bound-owner reconstruction changes the generated relationships.
pub(super) fn indexed(parents: Vec<Digest>, nested: bool) -> Result<Indexed> {
    indexed_uid(parents, nested, &[7])
}

fn indexed_uid(parents: Vec<Digest>, nested: bool, uid: &[u8]) -> Result<Indexed> {
    let plaintext = b"actual indexed file";
    let object = TERRANE_V1.calculate(IdentityKind::Chunk, plaintext)?;
    let digest = object.terrane_v1_digest()?;
    let file = LeafItem {
        key: b"file".to_vec(),
        entry: Entry {
            kind: EntryKind::File {
                mode: 0o644,
                size: plaintext.len() as u64,
                content: ContentRef::Inline(digest),
                link_id: None,
            },
            attrs: vec![Attribute {
                name: "uid",
                value: uid,
            }],
            attrs_present: true,
            xattrs: Vec::new(),
            xattrs_present: false,
            provenance: None,
        },
    };
    let mut trees = std::collections::BTreeMap::new();
    let (child, child_index) = owner(vec![file], &trees)?;
    let child_root = child.root;
    let node = terrane_core::tree_format::decode_node_for(
        child.nodes.get(&child_root).ok_or("missing child owner")?,
        true,
        262144,
        TreeUse::Ordinary,
    )?;
    let terrane_core::tree_format::NodeItems::Leaf(entries) = node.items else {
        return Err("small child is not a leaf".into());
    };
    let child_tree = Tree::build(entries, node.props, 262144, TreeUse::Ordinary)?;
    assert_eq!(child_tree.root_identity(), child_root);
    trees.insert(child_root, child_tree);
    let (tree, data) = if nested {
        let entries = [b"left".as_slice(), b"right".as_slice()]
            .into_iter()
            .map(|key| LeafItem {
                key: key.to_vec(),
                entry: Entry {
                    kind: EntryKind::Tree {
                        root: child_root,
                        props: None,
                    },
                    attrs: Vec::new(),
                    attrs_present: false,
                    xattrs: Vec::new(),
                    xattrs_present: false,
                    provenance: None,
                },
            })
            .collect();
        owner(entries, &trees)?
    } else {
        (child.clone(), child_index.clone())
    };
    let root = tree.root;
    let mut nodes = std::collections::BTreeMap::new();
    nodes.extend(child.nodes.clone());
    nodes.extend(tree.nodes.clone());
    nodes.extend(child_index.nodes.clone());
    nodes.extend(data.nodes.clone());
    let mut request = super::super::tests::request(parents);
    request.commit.tree = root;
    request.uploads = nodes
        .into_values()
        .map(|bytes| StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes,
        })
        .collect();
    request.uploads.push(StagedUpload::Chunk {
        encoded: terrane_core::codec::encode_envelope(terrane_core::codec::EncodedChunk {
            codec: terrane_core::codec::Codec::Raw,
            body: plaintext,
        }),
        identity: object,
        declared_plaintext_len: plaintext.len(),
        position: crate::store::ChunkPosition::Final,
        profile: Box::new(terrane_core::chunking::ChunkProfile::cdc_1m([0; 32])),
    });
    Ok(Indexed {
        request,
        owner: root,
        primary: data.root,
        index_nodes: data.nodes,
    })
}

#[derive(Clone)]
struct OwnedNamespace {
    root: Digest,
    nodes: std::collections::BTreeMap<Digest, Vec<u8>>,
}

fn owner<'a>(
    entries: Vec<LeafItem<'a>>,
    children: &std::collections::BTreeMap<Digest, Tree<'a>>,
) -> Result<(OwnedNamespace, evaluation::IndexData)> {
    const ACL: &[u8] = b"\x81\x82\x66writer\x18\x1f";
    const INDEX: &[u8] = b"\x81\x63uid";
    const DOMAIN: &[u8] = b"\x66public";
    let properties = vec![
        Property {
            name: "acl",
            value: ACL,
        },
        Property {
            name: "index",
            value: INDEX,
        },
        Property {
            name: "domain",
            value: DOMAIN,
        },
    ];
    let unbound = Tree::build(
        entries.clone(),
        Some(properties.clone()),
        262144,
        TreeUse::Ordinary,
    )?;
    let mut sources = children.clone();
    sources.insert(unbound.root_identity(), unbound.clone());
    let recipe = IndexEvaluationRecipe::new(unbound.root_identity(), "uid")?;
    let context = SemanticContext::new(3, 2, 1)?;
    let data = evaluation::construct(&recipe, &sources, 262144, context)?;
    let mut value = Vec::new();
    terrane_core::cbor::write_map(&mut value, 1);
    terrane_core::cbor::write_text(&mut value, "uid");
    terrane_core::cbor::write_text(
        &mut value,
        &data
            .root
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    );
    let binding = IndexRoots::decode_value(&value)?.encode_binding()?;
    let mut bound_properties = properties;
    bound_properties.push(Property {
        name: "index-roots",
        value: &binding,
    });
    let bound = Tree::build(entries, Some(bound_properties), 262144, TreeUse::Ordinary)?;
    let root = bound.root_identity();
    let mut calibrated = children.clone();
    calibrated.insert(root, bound.clone());
    let repeated = evaluation::construct(
        &IndexEvaluationRecipe::new(root, "uid")?,
        &calibrated,
        262144,
        context,
    )?;
    assert_eq!(repeated.root, data.root);
    assert_eq!(repeated.nodes, data.nodes);
    let nodes = bound
        .nodes()
        .map(|node| (node.identity(), node.encoded().to_vec()))
        .collect();
    Ok((OwnedNamespace { root, nodes }, data))
}

/// Constructs all four genuine immutable index roles without granting completion.
///
/// # Errors
/// Returns canonical namespace, recipe or relationship-construction failures.
///
/// # Panics
/// Panics if the independent bound-owner reconstruction differs from the generated index.
pub(super) fn mixed_role_index_data() -> Result<evaluation::IndexData> {
    let object = [9; 32];
    let entries = [Some(7u8), None]
        .into_iter()
        .enumerate()
        .map(|(position, value)| LeafItem {
            key: format!("file-{position}").into_bytes(),
            entry: Entry {
                kind: EntryKind::File {
                    mode: 0o644,
                    size: 1,
                    content: ContentRef::Inline(object),
                    link_id: None,
                },
                attrs: if value.is_some() {
                    vec![Attribute {
                        name: "uid",
                        value: &[7],
                    }]
                } else {
                    Vec::new()
                },
                attrs_present: value.is_some(),
                xattrs: Vec::new(),
                xattrs_present: false,
                provenance: None,
            },
        })
        .collect();
    let (_, data) = owner(entries, &std::collections::BTreeMap::new())?;
    Ok(data)
}

/// Binds a real namespace to a genuine index constructed from different attributes.
///
/// # Errors
/// Returns real tree/binding/recipe failures, never a fabricated completion.
///
/// # Panics
/// Panics if distinct actual attribute values produce identical primary relationships.
pub(super) fn divergent_index() -> Result<Indexed> {
    let mut actual = indexed(Vec::new(), false)?;
    let other = indexed_uid(Vec::new(), false, &[8])?;
    assert_ne!(actual.primary, other.primary);
    let owner_bytes = actual
        .request
        .uploads
        .iter()
        .find_map(|upload| match upload {
            StagedUpload::Meta {
                kind: IdentityKind::Node,
                bytes,
            } if TERRANE_V1
                .calculate(IdentityKind::Node, bytes)
                .is_ok_and(|identity| {
                    identity
                        .terrane_v1_digest()
                        .is_ok_and(|digest| digest == actual.owner)
                }) =>
            {
                Some(bytes)
            }
            _ => None,
        })
        .ok_or("actual owner missing")?;
    let node =
        terrane_core::tree_format::decode_node_for(owner_bytes, true, 262144, TreeUse::Ordinary)?;
    let terrane_core::tree_format::NodeItems::Leaf(entries) = node.items else {
        return Err("fixture owner is not leaf".into());
    };
    let mut value = Vec::new();
    terrane_core::cbor::write_map(&mut value, 1);
    terrane_core::cbor::write_text(&mut value, "uid");
    terrane_core::cbor::write_text(
        &mut value,
        &other
            .primary
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    );
    let binding = IndexRoots::decode_value(&value)?.encode_binding()?;
    let mut properties = node.props.ok_or("missing actual root properties")?;
    let selected = properties
        .iter_mut()
        .find(|property| property.name == "index-roots")
        .ok_or("missing local binding")?;
    selected.value = &binding;
    let rebuilt = Tree::build(entries, Some(properties), 262144, TreeUse::Ordinary)?;
    let replacement_owner = rebuilt.root_identity();
    let replacement_nodes = rebuilt
        .nodes()
        .map(|node| node.encoded().to_vec())
        .collect::<Vec<_>>();
    drop(rebuilt);
    actual.owner = replacement_owner;
    actual.request.commit.tree = replacement_owner;
    for bytes in replacement_nodes {
        actual.request.uploads.push(StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes,
        });
    }
    for bytes in other.index_nodes.values() {
        actual.request.uploads.push(StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes: bytes.clone(),
        });
    }
    // Distinct immutable addresses are staged once through the real batch route.
    let mut seen = std::collections::HashSet::new();
    let mut unique = Vec::new();
    for upload in actual.request.uploads {
        let retain = match &upload {
            StagedUpload::Meta { kind, bytes } => seen.insert(TERRANE_V1.calculate(*kind, bytes)?),
            _ => true,
        };
        if retain {
            unique.push(upload);
        }
    }
    actual.request.uploads = unique;
    actual.primary = other.primary;
    Ok(actual)
}

/// Omits only the actual owner's local binding while retaining canonical required values.
///
/// The original genuine auxiliary closure remains ordinary immutable upload data;
/// it is never substituted for the absent owner-local association.
///
/// # Errors
/// Preserves actual namespace identity, physical decoding and tree construction failures.
///
/// # Panics
/// Panics if the constructed fixture did not contain exactly one local binding.
pub(super) fn missing_local_binding(parents: Vec<Digest>) -> Result<Indexed> {
    let mut proposal = indexed(parents, false)?;
    let original = TERRANE_V1.from_digest(IdentityKind::Node, &proposal.owner)?;
    let mut body = None;
    for upload in &proposal.request.uploads {
        if let StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes,
        } = upload
            && TERRANE_V1.calculate(IdentityKind::Node, bytes)? == original
        {
            body = Some(bytes.clone());
            break;
        }
    }
    let body = body.ok_or("constructed owner has no actual upload")?;
    let node = terrane_core::tree_format::decode_node_for(&body, true, 262144, TreeUse::Ordinary)?;
    let terrane_core::tree_format::NodeItems::Leaf(entries) = node.items else {
        return Err("small fixture owner is not leaf".into());
    };
    let mut properties = node.props.ok_or("required root has no properties")?;
    let previous = properties.len();
    properties.retain(|property| property.name != "index-roots");
    assert_eq!(properties.len() + 1, previous);
    assert!(properties.iter().any(|property| property.name == "index"));
    let tree = Tree::build(entries, Some(properties), 262144, TreeUse::Ordinary)?;
    let owner = tree.root_identity();
    assert_ne!(owner, proposal.owner);
    proposal.owner = owner;
    proposal.request.commit.tree = owner;
    for node in tree.nodes() {
        proposal.request.uploads.push(StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes: node.encoded().to_vec(),
        });
    }
    Ok(proposal)
}
