//! Canonical codecs for portable directory, tree, and delta objects.

use crate::model::{
    Acl, AclEntry, ContentLayout, Delta, Directory, DirectoryEntry, Extent, FileNode,
    FilesystemMetadata, Node, SparseContent, SymlinkNode, Tree, Xattr,
};
use crate::registry::{DescriptorRole, validate_descriptor_role, validate_required_features};
use crate::{FeatureRef, MediaType, ObjectDescriptor, ObjectDigest, PathName};

use super::cbor::{CanonicalCborError, DecodeLimits, Decoder, Encoder};

/// Encodes one directory object in its exact portable v1 CBOR form.
#[must_use]
pub fn encode_directory(directory: &Directory) -> Vec<u8> {
    let mut encoder = Encoder::new();
    encoder.array(3);
    encoder.unsigned(1);
    encode_metadata(&mut encoder, directory.metadata());
    encode_slice(&mut encoder, directory.entries(), encode_directory_entry);
    encoder.finish()
}

/// Decodes and validates one exact portable v1 directory object.
///
/// # Errors
///
/// Returns [`CanonicalCborError`] for a noncanonical/bounded-CBOR violation,
/// schema mismatch, closed-registry violation, or invalid directory semantics.
pub fn decode_directory(
    bytes: &[u8],
    limits: DecodeLimits,
) -> Result<Directory, CanonicalCborError> {
    let mut decoder = Decoder::new(bytes, limits)?;
    decoder.array(3)?;
    decoder.exact("directory version", 1)?;
    let metadata = decode_metadata(&mut decoder)?;
    let entries = decode_vec(&mut decoder, decode_directory_entry)?;
    decoder.finish()?;
    Directory::new(metadata, entries).map_err(|error| semantics("directory", error))
}

/// Encodes one tree object in its exact portable v1 CBOR form.
#[must_use]
pub fn encode_tree(tree: &Tree) -> Vec<u8> {
    let mut encoder = Encoder::new();
    encoder.array(3);
    encoder.unsigned(1);
    encode_descriptor(&mut encoder, tree.root());
    encode_slice(&mut encoder, tree.required_features(), encode_feature);
    encoder.finish()
}

/// Decodes and validates one exact portable v1 tree object.
///
/// # Errors
///
/// Returns [`CanonicalCborError`] for profile, schema, registry, or local tree
/// semantic violations. Graph reachability is validated separately.
pub fn decode_tree(bytes: &[u8], limits: DecodeLimits) -> Result<Tree, CanonicalCborError> {
    let mut decoder = Decoder::new(bytes, limits)?;
    decoder.array(3)?;
    decoder.exact("tree version", 1)?;
    let root = decode_descriptor_for_role(&mut decoder, DescriptorRole::TreeRoot)?;
    let required_features = decode_vec(&mut decoder, decode_feature)?;
    decoder.finish()?;
    validate_features(&required_features)?;
    Tree::new(root, required_features).map_err(|error| semantics("tree", error))
}

/// Encodes one final-tree delta in its exact portable v1 CBOR form.
#[must_use]
pub fn encode_delta(delta: &Delta) -> Vec<u8> {
    let mut encoder = Encoder::new();
    encoder.array(5);
    encoder.unsigned(1);
    encode_descriptor(&mut encoder, delta.base());
    encode_descriptor(&mut encoder, delta.result());
    encode_slice(&mut encoder, delta.added_objects(), encode_descriptor);
    encode_slice(&mut encoder, delta.required_features(), encode_feature);
    encoder.finish()
}

/// Decodes and validates one exact portable v1 final-tree delta.
///
/// # Errors
///
/// Returns [`CanonicalCborError`] for profile, schema, registry, or local delta
/// semantic violations. Base/result reachability is validated separately.
pub fn decode_delta(bytes: &[u8], limits: DecodeLimits) -> Result<Delta, CanonicalCborError> {
    let mut decoder = Decoder::new(bytes, limits)?;
    decoder.array(5)?;
    decoder.exact("delta version", 1)?;
    let base = decode_descriptor_for_role(&mut decoder, DescriptorRole::DeltaTree)?;
    let result = decode_descriptor_for_role(&mut decoder, DescriptorRole::DeltaTree)?;
    let added_objects = decode_vec(&mut decoder, decode_delta_added_object)?;
    let required_features = decode_vec(&mut decoder, decode_feature)?;
    decoder.finish()?;
    validate_features(&required_features)?;
    Delta::new(base, result, added_objects, required_features)
        .map_err(|error| semantics("delta", error))
}

pub(super) fn encode_descriptor(encoder: &mut Encoder, descriptor: &ObjectDescriptor) {
    encoder.array(4);
    encoder.text(descriptor.media_type().as_str());
    encoder.unsigned(1);
    encoder.bytes(descriptor.digest().as_bytes());
    encoder.unsigned(descriptor.encoded_size());
}

pub(super) fn decode_descriptor(
    decoder: &mut Decoder<'_>,
) -> Result<ObjectDescriptor, CanonicalCborError> {
    decoder.array(4)?;
    let media_type = MediaType::new(decoder.text(255)?.to_owned())
        .map_err(|error| semantics("descriptor media type", error))?;
    decoder.exact("descriptor digest algorithm", 1)?;
    let digest = exact_bytes::<32>(decoder, 32)?;
    let encoded_size = decoder.unsigned()?;
    Ok(ObjectDescriptor::new(
        media_type,
        ObjectDigest::from_bytes(digest),
        encoded_size,
    ))
}

pub(super) fn decode_descriptor_for_role(
    decoder: &mut Decoder<'_>,
    role: DescriptorRole,
) -> Result<ObjectDescriptor, CanonicalCborError> {
    let descriptor = decode_descriptor(decoder)?;
    validate_descriptor_role(role, &descriptor)
        .map_err(|error| semantics("descriptor role", error))?;
    Ok(descriptor)
}

pub(super) fn validate_features(features: &[FeatureRef]) -> Result<(), CanonicalCborError> {
    validate_required_features(features).map_err(|error| semantics("required feature", error))
}

fn decode_delta_added_object(
    decoder: &mut Decoder<'_>,
) -> Result<ObjectDescriptor, CanonicalCborError> {
    decode_descriptor_for_role(decoder, DescriptorRole::DeltaAddedObject)
}

pub(super) fn encode_feature(encoder: &mut Encoder, feature: &FeatureRef) {
    encoder.array(3);
    encoder.text(feature.namespace());
    encoder.unsigned(u64::from(feature.major()));
    encoder.unsigned(u64::from(feature.minor()));
}

pub(super) fn decode_feature(decoder: &mut Decoder<'_>) -> Result<FeatureRef, CanonicalCborError> {
    decoder.array(3)?;
    let namespace = decoder.text(255)?.to_owned();
    let major = unsigned_u32(decoder, "feature major")?;
    let minor = unsigned_u32(decoder, "feature minor")?;
    let feature =
        FeatureRef::new(namespace, major, minor).map_err(|error| semantics("feature", error))?;
    validate_features(std::slice::from_ref(&feature))?;
    Ok(feature)
}

pub(super) fn encode_path(encoder: &mut Encoder, path: &crate::RelativePath) {
    encoder.array(path.components().len());
    for component in path.components() {
        encoder.bytes(component.as_bytes());
    }
}

pub(super) fn decode_path(
    decoder: &mut Decoder<'_>,
) -> Result<crate::RelativePath, CanonicalCborError> {
    let length = decoder.array_len()?;
    let mut components = Vec::with_capacity(length);
    for _ in 0..length {
        let component = PathName::new(decoder.bytes(255)?.to_vec())
            .map_err(|error| semantics("path name", error))?;
        components.push(component);
    }
    crate::RelativePath::new(components).map_err(|error| semantics("relative path", error))
}

fn encode_metadata(encoder: &mut Encoder, metadata: &FilesystemMetadata) {
    encoder.array(7);
    encoder.unsigned(u64::from(metadata.mode()));
    encoder.unsigned(u64::from(metadata.uid()));
    encoder.unsigned(u64::from(metadata.gid()));
    encoder.signed(metadata.mtime_seconds());
    encoder.unsigned(u64::from(metadata.mtime_nanos()));
    encode_slice(encoder, metadata.xattrs(), encode_xattr);
    match metadata.acl() {
        Some(acl) => encode_acl(encoder, acl),
        None => encoder.null(),
    }
}

fn decode_metadata(decoder: &mut Decoder<'_>) -> Result<FilesystemMetadata, CanonicalCborError> {
    decoder.array(7)?;
    let mode = unsigned_u16(decoder, "metadata mode")?;
    let uid = unsigned_u32(decoder, "metadata uid")?;
    let gid = unsigned_u32(decoder, "metadata gid")?;
    let mtime_seconds = decoder.signed()?;
    let mtime_nanos = unsigned_u32(decoder, "metadata nanoseconds")?;
    let xattrs = decode_vec(decoder, decode_xattr)?;
    let acl = decoder.nullable(decode_acl)?;
    FilesystemMetadata::new(mode, uid, gid, mtime_seconds, mtime_nanos, xattrs, acl)
        .map_err(|error| semantics("filesystem metadata", error))
}

fn encode_xattr(encoder: &mut Encoder, xattr: &Xattr) {
    encoder.array(2);
    encoder.bytes(xattr.name());
    encoder.bytes(xattr.value());
}

fn decode_xattr(decoder: &mut Decoder<'_>) -> Result<Xattr, CanonicalCborError> {
    decoder.array(2)?;
    let name = decoder.bytes(255)?.to_vec();
    let value = decoder.bytes(1_048_576)?.to_vec();
    Xattr::new(name, value).map_err(|error| semantics("extended attribute", error))
}

fn encode_acl(encoder: &mut Encoder, acl: &Acl) {
    encode_slice(encoder, acl.entries(), encode_acl_entry);
}

fn decode_acl(decoder: &mut Decoder<'_>) -> Result<Acl, CanonicalCborError> {
    let entries = decode_vec(decoder, decode_acl_entry)?;
    Acl::new(entries).map_err(|error| semantics("ACL", error))
}

fn encode_acl_entry(encoder: &mut Encoder, entry: &AclEntry) {
    encoder.array(3);
    match entry {
        AclEntry::UserObject(permissions) => {
            encoder.unsigned(0);
            encoder.null();
            encoder.unsigned(u64::from(*permissions));
        }
        AclEntry::NamedUser { uid, permissions } => {
            encoder.unsigned(1);
            encoder.unsigned(u64::from(*uid));
            encoder.unsigned(u64::from(*permissions));
        }
        AclEntry::GroupObject(permissions) => {
            encoder.unsigned(2);
            encoder.null();
            encoder.unsigned(u64::from(*permissions));
        }
        AclEntry::NamedGroup { gid, permissions } => {
            encoder.unsigned(3);
            encoder.unsigned(u64::from(*gid));
            encoder.unsigned(u64::from(*permissions));
        }
        AclEntry::Mask(permissions) => {
            encoder.unsigned(4);
            encoder.null();
            encoder.unsigned(u64::from(*permissions));
        }
        AclEntry::Other(permissions) => {
            encoder.unsigned(5);
            encoder.null();
            encoder.unsigned(u64::from(*permissions));
        }
    }
}

fn decode_acl_entry(decoder: &mut Decoder<'_>) -> Result<AclEntry, CanonicalCborError> {
    decoder.array(3)?;
    let tag = decoder.closed("ACL tag", 5)?;
    let qualifier = decoder.nullable(|value| unsigned_u32(value, "ACL qualifier"))?;
    let permissions = unsigned_u8(decoder, "ACL permissions")?;
    let entry = match (tag, qualifier) {
        (0, None) => AclEntry::UserObject(permissions),
        (1, Some(uid)) => AclEntry::NamedUser { uid, permissions },
        (2, None) => AclEntry::GroupObject(permissions),
        (3, Some(gid)) => AclEntry::NamedGroup { gid, permissions },
        (4, None) => AclEntry::Mask(permissions),
        (5, None) => AclEntry::Other(permissions),
        _ => {
            return Err(CanonicalCborError::InvalidSemantics {
                object: "ACL entry",
                message: "qualifier is not applicable to the selected ACL tag".to_owned(),
            });
        }
    };
    entry
        .validate()
        .map_err(|error| semantics("ACL entry", error))
}

fn encode_directory_entry(encoder: &mut Encoder, entry: &DirectoryEntry) {
    encoder.array(2);
    encoder.bytes(entry.name.as_bytes());
    encode_node(encoder, &entry.node);
}

fn decode_directory_entry(decoder: &mut Decoder<'_>) -> Result<DirectoryEntry, CanonicalCborError> {
    decoder.array(2)?;
    let name = PathName::new(decoder.bytes(255)?.to_vec())
        .map_err(|error| semantics("directory name", error))?;
    let node = decode_node(decoder)?;
    Ok(DirectoryEntry { name, node })
}

fn encode_node(encoder: &mut Encoder, node: &Node) {
    match node {
        Node::File(file) => {
            encoder.array(4);
            encoder.unsigned(0);
            encode_metadata(encoder, &file.metadata);
            encode_content_layout(encoder, &file.content);
            match file.hardlink_group {
                Some(digest) => encoder.bytes(digest.as_bytes()),
                None => encoder.null(),
            }
        }
        Node::Directory(child) => {
            encoder.array(2);
            encoder.unsigned(1);
            encode_descriptor(encoder, child);
        }
        Node::Symlink(link) => {
            encoder.array(3);
            encoder.unsigned(2);
            encode_metadata(encoder, link.metadata());
            encoder.bytes(link.target());
        }
    }
}

fn decode_node(decoder: &mut Decoder<'_>) -> Result<Node, CanonicalCborError> {
    let offset = decoder.position();
    let length = decoder.array_len()?;
    let kind = decoder.closed("tree node kind", 2)?;
    match (kind, length) {
        (0, 4) => {
            let metadata = decode_metadata(decoder)?;
            let content = decode_content_layout(decoder)?;
            let hardlink_group = decoder
                .nullable(|value| exact_bytes::<32>(value, 32).map(ObjectDigest::from_bytes))?;
            Ok(Node::File(FileNode {
                metadata,
                content,
                hardlink_group,
            }))
        }
        (1, 2) => {
            decode_descriptor_for_role(decoder, DescriptorRole::DirectoryChild).map(Node::Directory)
        }
        (2, 3) => {
            let metadata = decode_metadata(decoder)?;
            let target = decoder.bytes(4_096)?.to_vec();
            SymlinkNode::new(metadata, target)
                .map(Node::Symlink)
                .map_err(|error| semantics("symlink", error))
        }
        _ => Err(CanonicalCborError::ArrayLength {
            expected: match kind {
                0 => 4,
                1 => 2,
                2 => 3,
                _ => unreachable!("closed node kind"),
            },
            actual: length,
            offset,
        }),
    }
}

fn encode_content_layout(encoder: &mut Encoder, content: &ContentLayout) {
    match content {
        ContentLayout::Whole { content } => {
            encoder.array(2);
            encoder.unsigned(0);
            encode_descriptor(encoder, content);
        }
        ContentLayout::Sparse(sparse) => {
            encoder.array(3);
            encoder.unsigned(1);
            encoder.unsigned(sparse.logical_size());
            encode_slice(encoder, sparse.extents(), encode_extent);
        }
    }
}

fn decode_content_layout(decoder: &mut Decoder<'_>) -> Result<ContentLayout, CanonicalCborError> {
    let offset = decoder.position();
    let length = decoder.array_len()?;
    let kind = decoder.closed("content layout kind", 1)?;
    match (kind, length) {
        (0, 2) => decode_descriptor_for_role(decoder, DescriptorRole::FileContent)
            .map(ContentLayout::whole),
        (1, 3) => {
            let logical_size = decoder.unsigned()?;
            let extents = decode_vec(decoder, decode_extent)?;
            SparseContent::new(logical_size, extents)
                .map(ContentLayout::Sparse)
                .map_err(|error| semantics("sparse content", error))
        }
        _ => Err(CanonicalCborError::ArrayLength {
            expected: if kind == 0 { 2 } else { 3 },
            actual: length,
            offset,
        }),
    }
}

fn encode_extent(encoder: &mut Encoder, extent: &Extent) {
    encoder.array(3);
    encoder.unsigned(extent.offset());
    encoder.unsigned(extent.length());
    encode_descriptor(encoder, extent.content());
}

fn decode_extent(decoder: &mut Decoder<'_>) -> Result<Extent, CanonicalCborError> {
    decoder.array(3)?;
    let offset = decoder.unsigned()?;
    let length = decoder.unsigned()?;
    let content = decode_descriptor_for_role(decoder, DescriptorRole::FileContent)?;
    Extent::new(offset, length, content).map_err(|error| semantics("sparse extent", error))
}

pub(super) fn encode_slice<T>(encoder: &mut Encoder, values: &[T], encode: fn(&mut Encoder, &T)) {
    encoder.array(values.len());
    for value in values {
        encode(encoder, value);
    }
}

pub(super) fn decode_vec<T>(
    decoder: &mut Decoder<'_>,
    decode: fn(&mut Decoder<'_>) -> Result<T, CanonicalCborError>,
) -> Result<Vec<T>, CanonicalCborError> {
    let length = decoder.array_len()?;
    let mut values = Vec::with_capacity(length);
    for _ in 0..length {
        values.push(decode(decoder)?);
    }
    Ok(values)
}

pub(super) fn exact_bytes<const N: usize>(
    decoder: &mut Decoder<'_>,
    maximum: usize,
) -> Result<[u8; N], CanonicalCborError> {
    let bytes = decoder.bytes(maximum)?;
    bytes
        .try_into()
        .map_err(|_| CanonicalCborError::InvalidSemantics {
            object: "fixed byte string",
            message: format!("expected exactly {N} bytes, found {}", bytes.len()),
        })
}

fn unsigned_u8(decoder: &mut Decoder<'_>, object: &'static str) -> Result<u8, CanonicalCborError> {
    let value = decoder.unsigned()?;
    u8::try_from(value).map_err(|_| out_of_range(object, value))
}

fn unsigned_u16(
    decoder: &mut Decoder<'_>,
    object: &'static str,
) -> Result<u16, CanonicalCborError> {
    let value = decoder.unsigned()?;
    u16::try_from(value).map_err(|_| out_of_range(object, value))
}

pub(super) fn unsigned_u32(
    decoder: &mut Decoder<'_>,
    object: &'static str,
) -> Result<u32, CanonicalCborError> {
    let value = decoder.unsigned()?;
    u32::try_from(value).map_err(|_| out_of_range(object, value))
}

fn out_of_range(object: &'static str, value: u64) -> CanonicalCborError {
    CanonicalCborError::InvalidSemantics {
        object,
        message: format!("integer value {value} is outside its schema width"),
    }
}

pub(super) fn semantics(object: &'static str, error: impl std::fmt::Display) -> CanonicalCborError {
    CanonicalCborError::InvalidSemantics {
        object,
        message: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::descriptor_for_bytes;

    fn empty_metadata() -> FilesystemMetadata {
        FilesystemMetadata::new(0o755, 0, 0, 0, 0, Vec::new(), None)
            .unwrap_or_else(|error| panic!("test metadata failed: {error}"))
    }

    #[test]
    fn empty_directory_matches_rfc_golden_vector() {
        let directory = Directory::new(empty_metadata(), Vec::new())
            .unwrap_or_else(|error| panic!("test directory failed: {error}"));
        let encoded = encode_directory(&directory);

        assert_eq!(hex::encode(&encoded), "8301871901ed0000000080f680");
        let descriptor = descriptor_for_bytes(
            MediaType::new("application/vnd.aos.sandbox.directory.v1+cbor")
                .unwrap_or_else(|error| panic!("test media type failed: {error}")),
            &encoded,
        );
        assert_eq!(
            descriptor.digest().to_string(),
            "sha256:5853385fc82f12431186748ae0f949dd0c88afd3295ff9b2902bccbb3eacb69d"
        );
        assert_eq!(descriptor.encoded_size(), 13);
        assert_eq!(
            decode_directory(&encoded, DecodeLimits::default()),
            Ok(directory)
        );
    }

    #[test]
    fn decoder_rejects_noncanonical_directory_order() {
        let descriptor = ObjectDescriptor::new(
            MediaType::new("application/vnd.aos.sandbox.directory.v1+cbor")
                .unwrap_or_else(|error| panic!("test media type failed: {error}")),
            ObjectDigest::from_bytes([1; 32]),
            1,
        );
        let mut encoder = Encoder::new();
        encoder.array(3);
        encoder.unsigned(1);
        encode_metadata(&mut encoder, &empty_metadata());
        encoder.array(2);
        for name in [b"z".as_slice(), b"a".as_slice()] {
            encoder.array(2);
            encoder.bytes(name);
            encoder.array(2);
            encoder.unsigned(1);
            encode_descriptor(&mut encoder, &descriptor);
        }

        assert!(matches!(
            decode_directory(&encoder.finish(), DecodeLimits::default()),
            Err(CanonicalCborError::InvalidSemantics {
                object: "directory",
                ..
            })
        ));
    }

    #[test]
    fn unknown_node_kind_fails_closed() {
        let bytes = hex::decode("8301871901ed0000000080f6818241618103")
            .unwrap_or_else(|error| panic!("test hex failed: {error}"));

        assert!(matches!(
            decode_directory(&bytes, DecodeLimits::default()),
            Err(CanonicalCborError::UnknownRegistryValue {
                registry: "tree node kind",
                value: 3,
                ..
            })
        ));
    }

    #[test]
    fn unknown_required_feature_fails_closed() {
        let root = ObjectDescriptor::new(
            MediaType::new("application/vnd.aos.sandbox.directory.v1+cbor")
                .unwrap_or_else(|error| panic!("test media type failed: {error}")),
            ObjectDigest::from_bytes([1; 32]),
            1,
        );
        let feature = FeatureRef::new("example.invalid.feature", 1, 0)
            .unwrap_or_else(|error| panic!("test feature failed: {error}"));
        let tree = Tree::new(root, vec![feature])
            .unwrap_or_else(|error| panic!("test tree failed: {error}"));

        assert!(matches!(
            decode_tree(&encode_tree(&tree), DecodeLimits::default()),
            Err(CanonicalCborError::InvalidSemantics {
                object: "required feature",
                ..
            })
        ));
    }

    #[test]
    fn every_portable_mode_round_trips_to_identical_canonical_bytes() {
        for mode in 0..=0x0fff {
            let metadata = FilesystemMetadata::new(
                mode,
                u32::from(mode) * 65_537,
                u32::MAX - u32::from(mode),
                i64::from(mode) - 2_048,
                u32::from(mode) * 241_199,
                Vec::new(),
                None,
            )
            .unwrap_or_else(|error| panic!("generated metadata failed: {error}"));
            let directory = Directory::new(metadata, Vec::new())
                .unwrap_or_else(|error| panic!("generated directory failed: {error}"));
            let first = encode_directory(&directory);
            let decoded = decode_directory(&first, DecodeLimits::default())
                .unwrap_or_else(|error| panic!("generated directory decode failed: {error}"));

            assert_eq!(encode_directory(&decoded), first);
        }
    }
}
