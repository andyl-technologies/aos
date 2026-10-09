//! Bounded complete portable reconstruction graphs, without physical readback.
//!
//! Content objects have no reconstruction records. A Tree supplies exactly its
//! canonical Tree and every reachable Directory record, with no unused records,
//! cycles or unknown content layouts. Actual file bytes and filesystem metadata
//! still require the fixed domain owner's independent backing readback.

use std::collections::{BTreeMap, BTreeSet};

use aos_sandbox_core::{DecodeLimits, ObjectDescriptor, PortableMediaType};
use aos_sandbox_core::model::{ContentLayout, Node};

use super::{
    NIX_MAXIMUM_OBJECT_BYTES_V2, NIX_MAXIMUM_OBJECTS_V2, NixBuildSchemaErrorV2,
    NixStoreObjectV2,
};

const MAXIMUM_DIRECTORY_DEPTH: usize = 64;

pub(super) fn validate(object: &NixStoreObjectV2) -> Result<(), NixBuildSchemaErrorV2> {
    if object.portable.media_type().as_str() == PortableMediaType::Content.as_str() {
        return if object.portable_objects.is_empty()
            && object.portable.encoded_size() <= NIX_MAXIMUM_OBJECT_BYTES_V2
        {
            Ok(())
        } else {
            Err(NixBuildSchemaErrorV2::Invalid)
        };
    }

    let records = object
        .portable_objects
        .iter()
        .map(|record| (&record.descriptor, record.bytes.as_slice()))
        .collect::<BTreeMap<_, _>>();
    let tree_bytes = records
        .get(&object.portable)
        .ok_or(NixBuildSchemaErrorV2::Invalid)?;
    let tree = aos_sandbox_core::format::decode_tree(tree_bytes, DecodeLimits::default())
        .map_err(|_| NixBuildSchemaErrorV2::Invalid)?;

    let mut traversal = Traversal {
        records: &records,
        active: BTreeSet::new(),
        used: BTreeSet::from([object.portable.clone()]),
        logical_bytes: 0,
        nodes: 0,
    };
    traversal.directory(tree.root(), 0)?;
    if traversal.used.len() != records.len() {
        return Err(NixBuildSchemaErrorV2::Invalid);
    }

    Ok(())
}

struct Traversal<'records, 'bytes> {
    records: &'records BTreeMap<&'bytes ObjectDescriptor, &'bytes [u8]>,
    active: BTreeSet<ObjectDescriptor>,
    used: BTreeSet<ObjectDescriptor>,
    logical_bytes: u64,
    nodes: usize,
}

impl Traversal<'_, '_> {
    fn directory(
        &mut self,
        descriptor: &ObjectDescriptor,
        depth: usize,
    ) -> Result<(), NixBuildSchemaErrorV2> {
        self.count_node()?;
        if depth >= MAXIMUM_DIRECTORY_DEPTH
            || descriptor.media_type().as_str() != PortableMediaType::Directory.as_str()
            || !self.active.insert(descriptor.clone())
        {
            return Err(NixBuildSchemaErrorV2::Invalid);
        }

        let bytes = self
            .records
            .get(descriptor)
            .ok_or(NixBuildSchemaErrorV2::Invalid)?;
        let directory = aos_sandbox_core::format::decode_directory(bytes, DecodeLimits::default())
            .map_err(|_| NixBuildSchemaErrorV2::Invalid)?;
        self.used.insert(descriptor.clone());

        for entry in directory.entries() {
            self.count_node()?;
            match &entry.node {
                Node::Directory(child) => self.directory(child, depth + 1)?,
                Node::File(file) => {
                    // The first fixed domain streams complete raw Content.
                    // Sparse-layout support must join an actual backing reader
                    // before it can be accepted, not be silently flattened.
                    let ContentLayout::Whole { content } = &file.content else {
                        return Err(NixBuildSchemaErrorV2::Invalid);
                    };
                    if content.media_type().as_str() != PortableMediaType::Content.as_str() {
                        return Err(NixBuildSchemaErrorV2::Invalid);
                    }
                    self.logical_bytes = self
                        .logical_bytes
                        .checked_add(content.encoded_size())
                        .ok_or(NixBuildSchemaErrorV2::Invalid)?;
                    if self.logical_bytes > NIX_MAXIMUM_OBJECT_BYTES_V2 {
                        return Err(NixBuildSchemaErrorV2::Invalid);
                    }
                }
                Node::Symlink(_) => {}
            }
        }

        self.active.remove(descriptor);
        Ok(())
    }

    fn count_node(&mut self) -> Result<(), NixBuildSchemaErrorV2> {
        self.nodes = self.nodes.checked_add(1).ok_or(NixBuildSchemaErrorV2::Invalid)?;
        if self.nodes > NIX_MAXIMUM_OBJECTS_V2 {
            return Err(NixBuildSchemaErrorV2::Invalid);
        }

        Ok(())
    }
}
