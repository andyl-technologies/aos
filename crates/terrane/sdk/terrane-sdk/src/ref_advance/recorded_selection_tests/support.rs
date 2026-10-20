//! Reopens genuine native repositories with independently supplied per-view selections.

use super::*;
use crate::domain::DomainNamespace;
use crate::guard::{Guard, GuardConfig, ViewSelection};
use crate::ref_advance::{CommitTiming, Coordinator};
use crate::repository::{MetadataValidator, Repository};
use crate::store::{LocalFs, TokioClock, TokioLocalFs};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use terrane_format::auth::IssuerKey;
use terrane_format::properties::semantics::RecordedContext;
use terrane_format::tree_builder::Tree;
use terrane_format::tree_format::{Property, TreeUse};

/// Captures actual protected native setup, independently of selected lineage bytes.
pub(super) struct Location {
    namespace: DomainNamespace,
    control: PathBuf,
    owner: u32,
    keys: Vec<IssuerKey>,
    config: GuardConfig,
    current_snapshot: Vec<u8>,
}

impl Location {
    /// Captures the actual Original authority after genuine native publication.
    ///
    /// # Errors
    /// Preserves missing Original context and unavailable physical metadata failures.
    ///
    /// # Panics
    /// Panics if the Original authority names another bucket root or the selected
    /// current Guard snapshot contradicts the fixture profile.
    pub(super) async fn capture(repository: &Native, view: Digest) -> Result<Self> {
        let guard = repository.coordinator().guard();
        let original = guard.original_commit(&view)?;
        let authority = original.baseline().authority();
        let root = repository.coordinator().store().root().to_owned();
        assert_eq!(authority.root(), root);
        let owner = TokioLocalFs.symlink_metadata(&root).await?.uid();
        Ok(Self {
            namespace: DomainNamespace {
                root,
                domain: guard.config().storage_domain.clone(),
            },
            control: authority.control().to_owned(),
            owner,
            keys: guard.keys().to_vec(),
            config: guard.config().clone(),
            current_snapshot: crate::guard::recorded_native_fixture::current_snapshot(repository)
                .await?,
        })
    }

    /// Reopens existing physical and Original records without repairing missing evidence.
    ///
    /// # Errors
    /// Rejects unsupported or conflicting configured selections and unsafe or absent native records.
    ///
    /// # Panics
    /// Panics if the reopened current Guard snapshot contradicts the fixture
    /// profile or differs from the captured snapshot.
    pub(super) async fn reopen(
        &self,
        revision: u64,
        attribute_revision: u64,
        later: &[&str],
        selections: Vec<ViewSelection>,
    ) -> Result<Native> {
        let bucket = crate::bucket::FileBucket::open(
            crate::ref_advance::tests::config(self.namespace.root.clone()).await,
            TokioLocalFs,
            TokioClock,
            MetadataValidator::new((*self.config.chunk_profile).clone()),
        )
        .await?;
        let guard = Guard::new_active(bucket, TokioClock, self.keys.clone(), self.config.clone())
            .with_recorded_authoring(
                RecordedContext::new(revision, 3, later)?,
                attribute_revision,
            )?
            .with_view_selections(selections)?;
        let timing = CommitTiming::new(
            std::time::Duration::from_secs(30),
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(10),
        )?;
        let coordinator = Coordinator::new(guard, timing, TokioLocalFs);
        let repository = Repository::reopen_native_retention(
            coordinator,
            &self.namespace,
            &self.control,
            self.owner,
        )
        .await?;
        assert_eq!(
            crate::guard::recorded_native_fixture::current_snapshot(&repository).await?,
            self.current_snapshot
        );
        Ok(repository)
    }

    /// Names a genuine protected commit association for absence witnesses.
    pub(super) fn association(&self, view: Digest) -> PathBuf {
        self.control.join(format!(
            "commit-{}.cbor",
            view.iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        ))
    }

    /// Borrows the actual protected Original control directory.
    pub(super) fn control(&self) -> &std::path::Path {
        &self.control
    }
}

/// Captures the signed namespace root from independent full-history verification.
///
/// # Errors
/// Preserves signature, history, Original, producer and relationship failures.
pub(super) async fn signed_root(repository: &Native, view: Digest) -> Result<Digest> {
    Ok(repository
        .coordinator()
        .guard()
        .verified_tree(view)
        .await?
        .commit
        .commit()
        .tree)
}

/// Supplies an explicit immutable association from independently configured inputs.
///
/// # Errors
/// Rejects unsupported revisions, invalid trusted later names and incompatible attribute inputs.
pub(super) fn selected(
    view: Digest,
    root: Digest,
    revision: u64,
    attribute_revision: u64,
    later: &[&str],
) -> Result<ViewSelection> {
    Ok(ViewSelection::new(
        view,
        root,
        Selection::Recorded(RecordedContext::new(revision, 3, later)?),
        attribute_revision,
    )?)
}

/// Reads native ACK lineage while retaining its actual physical publication observation.
///
/// # Errors
/// Preserves missing lineage, invalid encoding and unavailable or changed physical observation failures.
pub(super) async fn lineage(repository: &Native) -> Result<CheckedLineage> {
    let holder = SingleHeld::acquire(repository.coordinator().store()).await?;
    let destination = holder.destination();
    let observed = destination.observe_publication().await?;
    let bytes = destination
        .selected_lineage(&observed, REFERENCE)
        .await?
        .ok_or("missing genuine native ACK lineage")?;
    let lineage = CheckedLineage::decode(&bytes)?;
    observed.revalidate().await?;
    Ok(lineage)
}

/// Rechecks full history and captures only the contexts genuinely completed by that invocation.
///
/// # Errors
/// Preserves full-history failures, incomplete pending traces and changed held observations.
pub(super) async fn completed(repository: &Native, head: Digest) -> Result<LineageUsedInputs> {
    let authority = repository
        .coordinator()
        .guard()
        .original_commit(&head)?
        .baseline()
        .authority()
        .clone();
    let holder = SingleHeld::acquire(repository.coordinator().store()).await?;
    let destination = holder.destination();
    let observed = destination.observe_publication().await?;
    let guard = repository
        .coordinator()
        .guard()
        .held_guard(holder.destination(), TokioClock)?;
    let consumed = ConsumedResolver::new(&guard, &authority)?;
    consumed.registration(&authority)?;
    guard
        .verified_history_observed(
            head,
            HistoryObservation::held(observed.identity()).tracked(&consumed),
        )
        .await?;
    let completed = consumed.finish()?;
    observed.revalidate().await?;
    Ok(completed)
}

/// Builds valid canonical later properties whose bytes are deliberately not active pointer bindings.
///
/// # Errors
/// Preserves canonical tree construction failures.
pub(super) fn inert_later_request(
    parents: Vec<Digest>,
) -> Result<crate::ref_advance::CommitRequest> {
    let tree = Tree::build(
        Vec::new(),
        Some(vec![
            Property {
                name: "acl",
                value: b"\x81\x82\x66writer\x18\x1f",
            },
            Property {
                name: "domain",
                value: b"\x66public",
            },
            Property {
                name: "index-roots",
                value: b"\x80",
            },
            Property {
                name: "index-gaps",
                value: b"\x80",
            },
        ]),
        262144,
        TreeUse::Ordinary,
    )?;
    let mut request = crate::ref_advance::tests::request(parents);
    request.commit.tree = tree.root_identity();
    request.uploads = tree
        .nodes()
        .map(|node| crate::ref_advance::StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes: node.encoded().to_vec(),
        })
        .collect();
    Ok(request)
}

/// Requires an authenticated readable hash side record for an already stored actual object.
///
/// # Errors
/// Preserves canonical file tree construction failures.
pub(super) fn hash_request(
    parent: Digest,
    object: Digest,
    plaintext: &[u8],
) -> Result<crate::ref_advance::CommitRequest> {
    use terrane_format::tree_format::{ContentRef, Entry, EntryKind, LeafItem};

    let identity = TERRANE_V1.calculate(IdentityKind::Chunk, plaintext)?;
    if identity.terrane_v1_digest()? != object {
        return Err("provided plaintext contradicts the genuine producing object".into());
    }
    let size = u64::try_from(plaintext.len())?;
    let tree = Tree::build(
        vec![LeafItem {
            key: b"file".to_vec(),
            entry: Entry {
                kind: EntryKind::File {
                    mode: 0o600,
                    size,
                    content: ContentRef::Inline(object),
                    link_id: None,
                },
                attrs: Vec::new(),
                attrs_present: false,
                xattrs: Vec::new(),
                xattrs_present: false,
                provenance: None,
            },
        }],
        Some(vec![
            Property {
                name: "acl",
                value: b"\x81\x82\x66writer\x18\x1f",
            },
            Property {
                name: "domain",
                value: b"\x66public",
            },
            Property {
                name: "hashes",
                value: b"\x81\x66sha256",
            },
        ]),
        262144,
        TreeUse::Ordinary,
    )?;
    let mut request = crate::ref_advance::tests::request(vec![parent]);
    request.commit.tree = tree.root_identity();
    request.uploads = tree
        .nodes()
        .map(|node| crate::ref_advance::StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes: node.encoded().to_vec(),
        })
        .collect();
    // Existing object bytes still need actual candidate reference admission.
    // Reoffer the same immutable chunk, without inventing a domain record.
    request
        .uploads
        .push(crate::ref_advance::StagedUpload::Chunk {
            encoded: terrane_format::codec::encode_envelope(terrane_format::codec::EncodedChunk {
                codec: terrane_format::codec::Codec::Raw,
                body: plaintext,
            }),
            identity,
            declared_plaintext_len: plaintext.len(),
            position: crate::store::ChunkPosition::Final,
            profile: Box::new(terrane_format::chunking::ChunkProfile::cdc_1m([0; 32])),
        });
    Ok(request)
}

/// Builds repeated genuine grafts with independently encoded local retain overrides.
///
/// # Errors
/// Preserves canonical child/parent tree construction failures.
pub(super) fn grafted_later_request(
    parents: Vec<Digest>,
) -> Result<(crate::ref_advance::CommitRequest, Digest)> {
    use terrane_format::tree_format::{Entry, EntryKind, LeafItem};

    let child = inert_later_request(parents.clone())?;
    let child_root = child.commit.tree;
    let entries = [
        (b"left".as_slice(), b"\x67forever".as_slice()),
        (b"right".as_slice(), b"\x62gc".as_slice()),
    ]
    .into_iter()
    .map(|(key, retain)| LeafItem {
        key: key.to_vec(),
        entry: Entry {
            kind: EntryKind::Tree {
                root: child_root,
                props: Some(vec![Property {
                    name: "retain",
                    value: retain,
                }]),
            },
            attrs: Vec::new(),
            attrs_present: false,
            xattrs: Vec::new(),
            xattrs_present: false,
            provenance: None,
        },
    })
    .collect();
    let parent = Tree::build(
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
            Property {
                name: "index-roots",
                value: b"\x80",
            },
            Property {
                name: "index-gaps",
                value: b"\x80",
            },
        ]),
        262144,
        TreeUse::Ordinary,
    )?;
    let mut request = crate::ref_advance::tests::request(parents);
    request.commit.tree = parent.root_identity();
    request.uploads = child.uploads;
    request.uploads.extend(
        parent
            .nodes()
            .map(|node| crate::ref_advance::StagedUpload::Meta {
                kind: IdentityKind::Node,
                bytes: node.encoded().to_vec(),
            }),
    );
    Ok((request, child_root))
}
