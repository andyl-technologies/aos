//! Publishes an actual contextual layer and a distinct later ordinary current head.

use super::fs::ReadFs;
use crate::bucket::{FileBucket, FileBucketConfig, FileBucketPublicationConfig};
use crate::guard::{Guard, StagedUpload, ViewSelection};
use crate::ref_advance::tests::{request, request_file, token};
use crate::ref_advance::{CommitTiming, Coordinator};
use crate::repository::{MetadataValidator, PublishedOverlayLayer, Repository};
use crate::store::{LocalFs, TokioClock, TokioLocalFs};
use std::os::unix::fs::MetadataExt;
use std::time::Duration;
use terrane_format::refs::RefRecord;
use terrane_format::tree_builder::Tree;
use terrane_format::tree_format::{Entry, EntryKind, LeafItem, Property, TreeUse};

/// Names the actual observing production metadata backend.
pub(super) type Bucket = FileBucket<ReadFs, TokioClock, MetadataValidator>;

/// Preserves genuine fixture and verification errors.
pub(super) type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Names the independently selected current-policy reference.
pub(super) const REFERENCE: &str = "refs/heads/_/main";

/// Owns actual publication, native Original retention and filesystem observations.
pub(super) struct Fixture {
    /// Retains the genuine native repository.
    pub(super) repository: Repository<Bucket, TokioClock, ReadFs>,
    /// Observes real native DATA and closing requests.
    pub(super) fs: ReadFs,
    /// Names the actual signed ordinary ancestor.
    pub(super) base: RefRecord,
    /// Names the genuinely published unreferenced contextual layer.
    pub(super) layer: PublishedOverlayLayer,
    /// Names the distinct ordinary current ref, never substituted for the layer.
    pub(super) current: RefRecord,
}

impl Fixture {
    /// Publishes genuine ordinary ancestry, an overlay whiteout and a later head.
    ///
    /// # Errors
    /// Preserves actual publication, native initialization and storage failures.
    ///
    /// # Panics
    /// Panics if the shared genuine seed fixture cannot initialize.
    pub(super) async fn open() -> TestResult<Self> {
        let seed = crate::ref_advance::tests::fixture().await;
        let mut writer = seed.begin(REFERENCE, &token(), "sdk").await?;
        let base = seed
            .advance(&mut writer, request_file(Vec::new(), b"ordinary ancestor"))
            .await?;
        let source = seed.guard();
        let base_tree = source.verified_tree(base.commit).await?;
        let (selection, profile) =
            source.selected_view_context_for_tests(base.commit, base_tree.evidence.root)?;
        let authority = source.configured_original_authority()?;
        let owner = TokioLocalFs
            .symlink_metadata(authority.control())
            .await?
            .uid();
        let fs = ReadFs::default();
        let bucket = FileBucket::open(
            FileBucketConfig {
                root: source.store().root().to_owned(),
                publication_control: Some(FileBucketPublicationConfig {
                    operator_uid: owner,
                    control: None,
                }),
                chunk_profile_name: source.config().chunk_profile_name.clone(),
                chunk_profile: (*source.config().chunk_profile).clone(),
                locality: source.config().home.clone(),
            },
            fs.clone(),
            TokioClock,
            MetadataValidator::new((*source.config().chunk_profile).clone()),
        )
        .await?;
        let mut guard = Guard::new(
            bucket,
            TokioClock,
            source.keys().to_vec(),
            source.config().clone(),
        );
        guard.configured_current = source.configured_current;
        let guard =
            guard
                .with_legacy_authoring()?
                .with_view_selections(vec![ViewSelection::new(
                    base.commit,
                    base_tree.evidence.root,
                    selection,
                    profile.attribute_revision,
                )?])?;
        let coordinator = Coordinator::new(
            guard,
            CommitTiming::new(
                Duration::from_secs(30),
                Duration::from_secs(60),
                Duration::from_secs(10),
            )?,
            fs.clone(),
        );
        let repository = Repository::from_native_authority(coordinator, authority, owner).await?;
        let layer_tree = Tree::build(
            vec![LeafItem {
                key: b"file".to_vec(),
                entry: Entry {
                    kind: EntryKind::Whiteout,
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
            ]),
            262144,
            TreeUse::OverlayLayer,
        )?;
        let mut proposal = request(vec![base.commit]);
        proposal.commit.tree = layer_tree.root_identity();
        proposal.uploads = layer_tree
            .nodes()
            .map(|node| StagedUpload::Meta {
                kind: terrane_format::identity::IdentityKind::Node,
                bytes: node.encoded().to_vec(),
            })
            .collect();
        let mut writer = repository.begin(REFERENCE, &token(), "sdk").await?;
        let layer = repository
            .publish_overlay_layer(&mut writer, proposal)
            .await?;
        assert_eq!(layer.root, layer_tree.root_identity());
        let current = repository
            .commit_request(
                &mut writer,
                request_file(vec![base.commit], b"later current authority"),
            )
            .await?;
        assert_ne!(layer.commit, current.commit);
        Ok(Self {
            repository,
            fs,
            base,
            layer,
            current,
        })
    }

    /// Borrows the actual native Guard installed by the repository factory.
    pub(super) fn guard(&self) -> &Guard<Bucket, TokioClock> {
        self.repository.coordinator().guard()
    }
}
