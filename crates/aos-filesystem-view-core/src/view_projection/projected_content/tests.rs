//! Structural membership regressions over genuinely compiled test indexes.

use std::io::Cursor;

use aos_sandbox_core::format::encode_view;
use aos_sandbox_core::model::{
    CacheDomain, CacheDomainKind, ContentLayout, Extent, FilesystemMetadata, PresentationAction,
    SparseContent, View, ViewConsistency, ViewMutation, ViewSource,
};
use aos_sandbox_core::{
    CacheDomainId, DecodeLimits, FeatureRef, MediaType, ObjectDescriptor, ObjectDigest, PathName,
    RelativePath, Revision, ViewId, descriptor_for_bytes,
};

use super::*;
use crate::index::{IndexNode, IndexRecord, IndexStaging, StructuralIndexBuilder};
use crate::{
    IndexExpectation, ProjectionLimits, ValidatedIndex, compile_view_projection, validate_index,
};

struct Fixture {
    bytes: Vec<u8>,
    tree: ObjectDescriptor,
    root: ObjectDescriptor,
    whole: ObjectDescriptor,
    hidden: ObjectDescriptor,
    extents: [ObjectDescriptor; 2],
}

impl Fixture {
    fn new(whole_bytes: &[u8]) -> Self {
        let tree = descriptor("application/vnd.aos.sandbox.tree.v1+cbor", b"tree");
        let root = descriptor("application/vnd.aos.sandbox.directory.v1+cbor", b"root");
        let whole = descriptor("application/vnd.aos.sandbox.content.v1", whole_bytes);
        let hidden = descriptor("application/vnd.aos.sandbox.content.v1", b"hidden");
        let extents = [
            descriptor("application/vnd.aos.sandbox.content.v1", b"abc"),
            descriptor("application/vnd.aos.sandbox.content.v1", b"de"),
        ];
        let whole_layout = ContentLayout::whole(whole.clone());
        let hidden_layout = ContentLayout::whole(hidden.clone());
        let holes = ContentLayout::Sparse(SparseContent::new(20, Vec::new()).expect("holes"));
        let sparse = ContentLayout::Sparse(
            SparseContent::new(
                20,
                vec![
                    Extent::new(2, 3, extents[0].clone()).expect("first extent"),
                    Extent::new(8, 2, extents[1].clone()).expect("second extent"),
                    Extent::new(13, 3, extents[0].clone()).expect("repeated object"),
                ],
            )
            .expect("sparse layout"),
        );
        let directory_metadata =
            FilesystemMetadata::new(0o755, 10, 20, 30, 0, Vec::new(), None).expect("directory");
        let file_metadata =
            FilesystemMetadata::new(0o644, 10, 20, 30, 0, Vec::new(), None).expect("file");
        let link_metadata =
            FilesystemMetadata::new(0o777, 10, 20, 30, 0, Vec::new(), None).expect("link");
        let staging = IndexStaging::new(Cursor::new(Vec::new()), 64 * 1024, 4096);
        let mut builder =
            StructuralIndexBuilder::new(staging, [7; 32], tree.clone(), root.clone(), 0)
                .expect("builder");
        builder
            .push(&IndexRecord {
                parent: u64::MAX,
                depth: 0,
                sibling_ordinal: 0,
                name: &[],
                metadata: &directory_metadata,
                node: IndexNode::Directory { descriptor: &root },
            })
            .expect("root record");

        let records: [(&[u8], &FilesystemMetadata, IndexNode<'_>); 6] = [
            (
                b"dir",
                &directory_metadata,
                IndexNode::Directory { descriptor: &root },
            ),
            (
                b"hidden",
                &file_metadata,
                IndexNode::File {
                    content: &hidden_layout,
                    hardlink_group: None,
                },
            ),
            (
                b"holes",
                &file_metadata,
                IndexNode::File {
                    content: &holes,
                    hardlink_group: None,
                },
            ),
            (
                b"link",
                &link_metadata,
                IndexNode::Symlink { target: b"whole" },
            ),
            (
                b"sparse",
                &file_metadata,
                IndexNode::File {
                    content: &sparse,
                    hardlink_group: None,
                },
            ),
            (
                b"whole",
                &file_metadata,
                IndexNode::File {
                    content: &whole_layout,
                    hardlink_group: None,
                },
            ),
        ];
        for (ordinal, (name, metadata, node)) in records.into_iter().enumerate() {
            builder
                .push(&IndexRecord {
                    parent: 0,
                    depth: 1,
                    sibling_ordinal: ordinal as u32,
                    name,
                    metadata,
                    node,
                })
                .expect("child record");
        }

        let (writer, _) = builder.finish().expect("finish").into_parts();
        Self {
            bytes: writer.into_inner(),
            tree,
            root,
            whole,
            hidden,
            extents,
        }
    }

    fn validate(&self) -> ValidatedIndex<'_> {
        let index = descriptor(crate::INDEX_MEDIA_TYPE, &self.bytes);
        validate_index(
            &self.bytes,
            64 * 1024,
            1_048_576,
            &IndexExpectation {
                index: &index,
                compiler_abi: [7; 32],
                tree: &self.tree,
                root: &self.root,
                tree_features: 0,
            },
        )
        .expect("validated index")
    }

    fn projection<'index, 'bytes>(
        &self,
        index: &'index ValidatedIndex<'bytes>,
        actions: Vec<PresentationAction>,
        revision: u64,
    ) -> ValidatedViewProjection<'index, 'bytes> {
        let view = View::new(
            ViewSource::ImmutableTree {
                tree: self.tree.clone(),
            },
            actions,
            ViewConsistency::Immutable,
            ViewMutation::ReadOnly,
            FeatureRef::new("aos.sandbox.identity.posix32", 1, 0).expect("identity profile"),
            CacheDomain::new(CacheDomainKind::Private, CacheDomainId::from_bytes([3; 16])),
            Vec::new(),
        )
        .expect("View");
        let bytes = encode_view(&view);
        let descriptor = descriptor("application/vnd.aos.sandbox.view.v1+cbor", &bytes);
        compile_view_projection(
            &bytes,
            &descriptor,
            ViewId::from_bytes([4; 16]),
            Revision::new(revision),
            index,
            ProjectionLimits {
                decode: DecodeLimits {
                    maximum_bytes: 64 * 1024,
                    maximum_collection_items: 1024,
                    maximum_total_items: 4096,
                    maximum_byte_string_bytes: 64 * 1024,
                    maximum_text_bytes: 255,
                    maximum_depth: 32,
                },
                maximum_actions: 4,
                maximum_source_records: 128,
                maximum_projected_nodes: 128,
                maximum_path_components: 64,
                maximum_path_bytes: 1_048_576,
                maximum_working_bytes: 16 * 1_048_576,
            },
        )
        .expect("projection")
    }
}

fn descriptor(media: &str, bytes: &[u8]) -> ObjectDescriptor {
    descriptor_for_bytes(MediaType::new(media).expect("media type"), bytes)
}

fn path(names: &[&[u8]]) -> RelativePath {
    RelativePath::new(
        names
            .iter()
            .map(|name| PathName::new(name.to_vec()).expect("name"))
            .collect(),
    )
    .expect("path")
}

#[test]
fn projected_whole_object_retains_exact_view_mapping_and_content() {
    let fixture = Fixture::new(b"hello");
    let index = fixture.validate();
    let projection = fixture.projection(&index, Vec::new(), 1);
    let node = projection.lookup(&path(&[b"whole"])).expect("visible file");

    let proof = projection
        .prove_projected_file_object(node, &fixture.whole)
        .expect("membership")
        .expect("whole-file proof");

    assert_eq!(proof.projected(), node);
    assert!(proof.object().matches(&fixture.whole));
    assert_eq!(
        (proof.logical_offset(), proof.length(), proof.logical_size()),
        (0, 5, 5)
    );
    assert_eq!(proof.view_descriptor(), projection.view_descriptor());
    assert_eq!(proof.view_identity(), projection.view_identity());
    assert_eq!(proof.disclosure(), projection.view().disclosure());
}

#[test]
fn hidden_source_retention_does_not_prove_visible_file_content() {
    let fixture = Fixture::new(b"hello");
    let index = fixture.validate();
    let projection = fixture.projection(
        &index,
        vec![PresentationAction::Exclude {
            destination: path(&[b"hidden"]),
        }],
        1,
    );
    let visible = projection.lookup(&path(&[b"whole"])).expect("visible file");

    assert!(
        projection
            .prove_source_object(&fixture.hidden)
            .expect("source retention")
            .is_some()
    );
    assert!(projection.lookup(&path(&[b"hidden"])).is_none());
    assert!(
        projection
            .prove_projected_file_object(visible, &fixture.hidden)
            .expect("membership")
            .is_none()
    );
}

#[test]
fn structural_nodes_and_synthetic_parents_cannot_prove_content() {
    let fixture = Fixture::new(b"hello");
    let index = fixture.validate();
    let projection = fixture.projection(
        &index,
        vec![PresentationAction::Include {
            source_prefix: path(&[b"whole"]),
            destination: path(&[b"mapped", b"file"]),
        }],
        1,
    );

    for name in [
        path(&[]),
        path(&[b"dir"]),
        path(&[b"link"]),
        path(&[b"mapped"]),
    ] {
        let node = projection.lookup(&name).expect("structural node");
        for object in [&fixture.whole, &fixture.root, &fixture.tree] {
            assert!(
                projection
                    .prove_projected_file_object(node, object)
                    .expect("membership")
                    .is_none()
            );
        }
    }
    let alias = projection
        .lookup(&path(&[b"mapped", b"file"]))
        .expect("included file");
    assert!(
        projection
            .prove_projected_file_object(alias, &fixture.whole)
            .expect("membership")
            .is_some()
    );
}

#[test]
fn projected_descriptor_substitutions_are_refused_for_whole_and_sparse_files() {
    let fixture = Fixture::new(b"hello");
    let index = fixture.validate();
    let projection = fixture.projection(&index, Vec::new(), 1);

    for (name, object) in [
        (b"whole".as_slice(), &fixture.whole),
        (b"sparse".as_slice(), &fixture.extents[0]),
    ] {
        let node = projection.lookup(&path(&[name])).expect("file");
        let substitutions = [
            ObjectDescriptor::new(
                MediaType::new("application/octet-stream").expect("media"),
                object.digest(),
                object.encoded_size(),
            ),
            ObjectDescriptor::new(
                object.media_type().clone(),
                ObjectDigest::from_bytes([99; 32]),
                object.encoded_size(),
            ),
            ObjectDescriptor::new(
                object.media_type().clone(),
                object.digest(),
                object.encoded_size() + 1,
            ),
        ];
        for substituted in substitutions {
            assert!(
                projection
                    .prove_projected_file_object(node, &substituted)
                    .expect("membership")
                    .is_none()
            );
        }
        for structural in [&fixture.root, &fixture.tree] {
            assert!(
                projection
                    .prove_projected_file_object(node, structural)
                    .expect("membership")
                    .is_none()
            );
        }
    }
}

#[test]
fn projected_sparse_proofs_bind_first_exact_extent_and_leave_holes_unbacked() {
    let fixture = Fixture::new(b"hello");
    let index = fixture.validate();
    let projection = fixture.projection(&index, Vec::new(), 1);
    let sparse = projection.lookup(&path(&[b"sparse"])).expect("sparse file");

    for (object, offset, length) in [(&fixture.extents[0], 2, 3), (&fixture.extents[1], 8, 2)] {
        let proof = projection
            .prove_projected_file_object(sparse, object)
            .expect("membership")
            .expect("extent");
        assert_eq!(
            (proof.logical_offset(), proof.length(), proof.logical_size()),
            (offset, length, 20)
        );
    }
    let holes = projection
        .lookup(&path(&[b"holes"]))
        .expect("hole-only file");
    for object in [&fixture.whole, &fixture.extents[0], &fixture.extents[1]] {
        assert!(
            projection
                .prove_projected_file_object(holes, object)
                .expect("membership")
                .is_none()
        );
    }
}

#[test]
fn foreign_revision_or_mapping_cannot_substitute_for_the_retained_projection() {
    let fixture = Fixture::new(b"hello");
    let index = fixture.validate();
    let original = fixture.projection(&index, Vec::new(), 1);
    let successor = fixture.projection(&index, Vec::new(), 2);
    let foreign = successor
        .lookup(&path(&[b"whole"]))
        .expect("successor file");

    assert!(matches!(
        original.prove_projected_file_object(foreign, &fixture.whole),
        Err(ProjectionError::UnresolvedPath)
    ));
    let mut changed = original
        .lookup(&path(&[b"whole"]))
        .expect("original file")
        .clone();
    changed.kind = super::super::ProjectedNodeKind::Source {
        record_id: 1,
        kind: crate::IndexNodeKind::File,
    };
    assert!(matches!(
        original.prove_projected_file_object(&changed, &fixture.whole),
        Err(ProjectionError::UnresolvedPath)
    ));

    let retained = original.lookup(&path(&[b"whole"])).expect("original file");
    assert_eq!(
        original
            .prove_projected_file_object(retained, &fixture.whole)
            .expect("membership")
            .expect("original proof")
            .view_identity()
            .1,
        Revision::new(1)
    );
}

#[test]
fn empty_whole_content_is_structural_membership_not_a_nonempty_range() {
    let fixture = Fixture::new(b"");
    let index = fixture.validate();
    let projection = fixture.projection(&index, Vec::new(), 1);
    let node = projection.lookup(&path(&[b"whole"])).expect("empty file");

    let proof = projection
        .prove_projected_file_object(node, &fixture.whole)
        .expect("membership")
        .expect("empty whole object");

    assert_eq!(
        (proof.logical_offset(), proof.length(), proof.logical_size()),
        (0, 0, 0)
    );
}
