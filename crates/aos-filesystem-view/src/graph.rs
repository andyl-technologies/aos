//! Iterative whole-graph validation and structural-index compilation.

use std::cmp::Ordering;
use std::collections::{BTreeMap, VecDeque};
use std::io::{Seek, Write};

use aos_sandbox_core::format::{StreamingDirectory, decode_tree};
use aos_sandbox_core::model::{AclEntry, ContentLayout, FilesystemMetadata, Node};
use aos_sandbox_core::{
    CanonicalCborError, DecodeLimits, DescriptorRole, FeatureRef, ObjectDescriptor, ObjectDigest,
    PathName, RelativePath, hardlink_group_digest, validate_descriptor_role,
};

use crate::index::{
    FEATURE_ABSOLUTE_SYMLINK, FEATURE_ACL, FEATURE_PARENT_SYMLINK, IndexError, IndexNode,
    IndexRecord, IndexStaging, StagedIndex, StructuralIndexBuilder, byte_vector_charge,
    record_encoded_len,
};
use crate::limits::TreeCompileLimits;
use crate::source::{ObjectSource, SourceError, load_exact};

const ACL_FEATURE: &str = "aos.sandbox.metadata.posix-acl";
const ABSOLUTE_SYMLINK_FEATURE: &str = "aos.sandbox.symlink.absolute";
const PARENT_SYMLINK_FEATURE: &str = "aos.sandbox.symlink.parent-escape";

/// Compiles hostile portable trees under explicit whole-graph limits.
#[derive(Clone, Copy, Debug)]
pub struct TreeCompiler {
    limits: TreeCompileLimits,
}

impl TreeCompiler {
    /// Constructs a compiler with caller-selected hard limits.
    #[must_use]
    pub const fn new(limits: TreeCompileLimits) -> Self {
        Self { limits }
    }

    /// Validates an exact tree graph into a consumed private staging writer.
    ///
    /// The walk is iterative. Only unresolved directory work and hard-link
    /// membership remain in heap; both are charged to `working_bytes` before
    /// retention. Each directory's entries are decoded one at a time.
    ///
    /// # Errors
    ///
    /// Returns [`CompileError`] for source-integrity, canonical-format,
    /// graph-cycle, feature, hard-link, ACL, resource, or index failures.
    pub fn compile<S, W>(
        &self,
        source: &mut S,
        staging: IndexStaging<W>,
        tree_descriptor: &ObjectDescriptor,
        compiler_abi: [u8; 32],
    ) -> Result<(CompileSummary, StagedIndex<W>), CompileError<S::Error>>
    where
        S: ObjectSource,
        W: Write + Seek,
    {
        validate_descriptor_role(DescriptorRole::ImmutableViewSource, tree_descriptor)
            .map_err(|_| CompileError::InvalidTreeDescriptor)?;
        let tree_reservation = object_reservation(tree_descriptor)?;
        enforce(tree_reservation, self.limits.working_bytes, "working bytes")?;
        let tree_bytes = load_exact(source, tree_descriptor, self.limits.object_bytes)?;
        let tree = decode_tree(tree_bytes.bytes(), self.decode_limits())?;
        let features = tree.required_features().to_vec();
        let feature_bits = validate_tree_features(&features)?;
        let root_descriptor = tree.root().clone();
        let retained_tree = tree_retained_charge(&root_descriptor, &features)?;
        let maximum_tree_bytes = tree_reservation.max(retained_tree);
        drop(tree);
        drop(tree_bytes);
        let mut index = StructuralIndexBuilder::new_v3(
            staging.narrow(
                self.limits.index_bytes,
                self.limits.index_record_bytes,
                self.limits.working_bytes,
            ),
            compiler_abi,
            tree_descriptor.clone(),
            root_descriptor.clone(),
            feature_bits,
        )?;
        let initial_working_bytes = checked_add(
            retained_tree,
            index.retained_working_bytes()?,
            "working bytes",
        )?;
        enforce(
            initial_working_bytes,
            self.limits.working_bytes,
            "working bytes",
        )?;

        let mut state = WalkState {
            working_bytes: initial_working_bytes,
            maximum_working_bytes: maximum_tree_bytes.max(initial_working_bytes),
            ..WalkState::default()
        };
        self.charge_node(&mut state)?;
        let root_charge = work_charge::<S::Error>(&[], None, &[])?;
        let root_working = checked_add(state.working_bytes, root_charge, "working bytes")?;
        enforce(root_working, self.limits.working_bytes, "working bytes")?;
        state.working_bytes = root_working;
        state.maximum_working_bytes = state.maximum_working_bytes.max(root_working);
        let root = Work {
            descriptor: root_descriptor,
            parent: u64::MAX,
            depth: 0,
            sibling_ordinal: 0,
            name: None,
            path: Vec::new(),
            ancestors: Vec::new(),
            charged_bytes: root_charge,
        };
        state.queue.push_back(root);

        while let Some(work) = state.queue.pop_back() {
            state.working_bytes = state
                .working_bytes
                .checked_sub(work.charged_bytes)
                .ok_or(CompileError::InternalAccounting)?;
            self.visit_directory(source, &mut index, &features, work, &mut state)?;
        }

        validate_hardlinks(&mut state, self.limits.working_bytes)?;
        let summary = CompileSummary {
            nodes: state.nodes,
            directories: state.directories,
            logical_bytes: state.logical_bytes,
            name_bytes: state.name_bytes,
            xattr_bytes: state.xattr_bytes,
            acl_entries: state.acl_entries,
            extents: state.extents,
            hardlink_groups: state.hardlinks.len() as u64,
            maximum_working_bytes: state.maximum_working_bytes,
        };
        let index_retained = index.retained_working_bytes()?;
        let external_working = state
            .working_bytes
            .checked_sub(index_retained)
            .ok_or(CompileError::InternalAccounting)?;
        let finish_working = checked_add(
            state.working_bytes,
            index.finish_temporary_working_bytes()?,
            "working bytes",
        )?;
        enforce(finish_working, self.limits.working_bytes, "working bytes")?;
        let finished = index.finish_with_external(external_working, self.limits.working_bytes)?;
        let summary = CompileSummary {
            maximum_working_bytes: summary
                .maximum_working_bytes
                .max(finish_working)
                .max(finished.peak_working_bytes),
            ..summary
        };
        Ok((summary, finished.staged))
    }

    fn visit_directory<S, W>(
        &self,
        source: &mut S,
        index: &mut StructuralIndexBuilder<W>,
        features: &[FeatureRef],
        work: Work,
        state: &mut WalkState,
    ) -> Result<(), CompileError<S::Error>>
    where
        S: ObjectSource,
        W: Write + Seek,
    {
        if work.ancestors.contains(&work.descriptor.digest()) {
            return Err(CompileError::Cycle);
        }
        if work.depth > self.limits.depth {
            return Err(CompileError::LimitExceeded("depth"));
        }
        let object_charge = object_reservation(&work.descriptor)?;
        let with_object = checked_add(state.working_bytes, object_charge, "working bytes")?;
        enforce(with_object, self.limits.working_bytes, "working bytes")?;
        state.working_bytes = with_object;
        state.maximum_working_bytes = state.maximum_working_bytes.max(with_object);
        let object = load_exact(source, &work.descriptor, self.limits.object_bytes)?;
        let mut directory = StreamingDirectory::new(object.bytes(), self.decode_limits())?;
        if directory.remaining() as u64 > self.limits.directory_entries {
            return Err(CompileError::LimitExceeded("directory entries"));
        }
        self.charge_metadata(directory.metadata(), features, state)?;
        state.directories = checked_add(state.directories, 1, "directories")?;

        let directory_record = IndexRecord {
            parent: work.parent,
            depth: work.depth,
            sibling_ordinal: work.sibling_ordinal,
            name: work.name.as_ref().map_or(&[], PathName::as_bytes),
            metadata: directory.metadata(),
            node: IndexNode::Directory {
                descriptor: &work.descriptor,
            },
        };
        let directory_id = push_index(index, &directory_record, state, self.limits.working_bytes)?;

        let mut ancestors = work.ancestors;
        ancestors.push(work.descriptor.digest());
        let mut sibling_ordinal = 0_u32;
        while let Some(entry) = directory.next_entry()? {
            let scratch_charge = next_work_charge(&work.path, &entry.name, &ancestors)?;
            let with_scratch = checked_add(state.working_bytes, scratch_charge, "working bytes")?;
            enforce(with_scratch, self.limits.working_bytes, "working bytes")?;
            state.working_bytes = with_scratch;
            state.maximum_working_bytes = state.maximum_working_bytes.max(with_scratch);
            let mut path = work.path.clone();
            path.push(entry.name.clone());
            state.name_bytes = checked_add(
                state.name_bytes,
                entry.name.as_bytes().len() as u64,
                "name bytes",
            )?;
            enforce(state.name_bytes, self.limits.name_bytes, "name bytes")?;
            let depth = work
                .depth
                .checked_add(1)
                .ok_or(CompileError::LimitExceeded("depth"))?;
            if depth > self.limits.depth {
                return Err(CompileError::LimitExceeded("depth"));
            }

            match entry.node {
                Node::Directory(descriptor) => {
                    self.charge_node(state)?;
                    state.queue.push_back(Work {
                        descriptor,
                        parent: directory_id,
                        depth,
                        sibling_ordinal,
                        name: path.last().cloned(),
                        path,
                        ancestors: ancestors.clone(),
                        charged_bytes: scratch_charge,
                    });
                }
                Node::File(file) => {
                    self.charge_node(state)?;
                    self.charge_metadata(&file.metadata, features, state)?;
                    let logical = file.content.logical_size();
                    state.logical_bytes =
                        checked_add(state.logical_bytes, logical, "logical bytes")?;
                    enforce(
                        state.logical_bytes,
                        self.limits.logical_bytes,
                        "logical bytes",
                    )?;
                    if let ContentLayout::Sparse(sparse) = &file.content {
                        state.extents =
                            checked_add(state.extents, sparse.extents().len() as u64, "extents")?;
                        enforce(state.extents, self.limits.extents, "extents")?;
                    }
                    if let Some(group) = file.hardlink_group {
                        self.add_hardlink(state, group, &path, &file.metadata, &file.content)?;
                    }
                    let record = IndexRecord {
                        parent: directory_id,
                        depth,
                        sibling_ordinal,
                        name: entry.name.as_bytes(),
                        metadata: &file.metadata,
                        node: IndexNode::File {
                            content: &file.content,
                            hardlink_group: file.hardlink_group,
                        },
                    };
                    push_index(index, &record, state, self.limits.working_bytes)?;
                    state.working_bytes = state
                        .working_bytes
                        .checked_sub(scratch_charge)
                        .ok_or(CompileError::InternalAccounting)?;
                }
                Node::Symlink(link) => {
                    self.charge_node(state)?;
                    self.charge_metadata(link.metadata(), features, state)?;
                    let target_bytes = link.target().len() as u64;
                    state.symlink_bytes =
                        checked_add(state.symlink_bytes, target_bytes, "symlink bytes")?;
                    enforce(
                        state.symlink_bytes,
                        self.limits.symlink_bytes,
                        "symlink bytes",
                    )?;
                    validate_symlink(link.target(), &path, features)?;
                    let record = IndexRecord {
                        parent: directory_id,
                        depth,
                        sibling_ordinal,
                        name: entry.name.as_bytes(),
                        metadata: link.metadata(),
                        node: IndexNode::Symlink {
                            target: link.target(),
                        },
                    };
                    push_index(index, &record, state, self.limits.working_bytes)?;
                    state.working_bytes = state
                        .working_bytes
                        .checked_sub(scratch_charge)
                        .ok_or(CompileError::InternalAccounting)?;
                }
            }
            sibling_ordinal = sibling_ordinal
                .checked_add(1)
                .ok_or(CompileError::LimitExceeded("directory entries"))?;
        }
        state.working_bytes = state
            .working_bytes
            .checked_sub(object_charge)
            .ok_or(CompileError::InternalAccounting)?;
        Ok(())
    }

    fn charge_node<E>(&self, state: &mut WalkState) -> Result<(), CompileError<E>>
    where
        E: std::error::Error + 'static,
    {
        state.nodes = checked_add(state.nodes, 1, "nodes")?;
        enforce(state.nodes, self.limits.nodes, "nodes")
    }

    fn charge_metadata<E>(
        &self,
        metadata: &FilesystemMetadata,
        features: &[FeatureRef],
        state: &mut WalkState,
    ) -> Result<(), CompileError<E>>
    where
        E: std::error::Error + 'static,
    {
        state.xattrs = checked_add(state.xattrs, metadata.xattrs().len() as u64, "xattrs")?;
        enforce(state.xattrs, self.limits.xattrs, "xattrs")?;
        for xattr in metadata.xattrs() {
            state.xattr_bytes = checked_add(
                state.xattr_bytes,
                (xattr.name().len() + xattr.value().len()) as u64,
                "xattr bytes",
            )?;
        }
        enforce(state.xattr_bytes, self.limits.xattr_bytes, "xattr bytes")?;

        if let Some(acl) = metadata.acl() {
            require_feature(features, ACL_FEATURE)?;
            validate_acl_mode(metadata)?;
            state.acl_entries =
                checked_add(state.acl_entries, acl.entries().len() as u64, "ACL entries")?;
            enforce(state.acl_entries, self.limits.acl_entries, "ACL entries")?;
        }
        Ok(())
    }

    fn add_hardlink<E>(
        &self,
        state: &mut WalkState,
        group: ObjectDigest,
        path: &[PathName],
        metadata: &FilesystemMetadata,
        content: &ContentLayout,
    ) -> Result<(), CompileError<E>>
    where
        E: std::error::Error + 'static,
    {
        let is_new = !state.hardlinks.contains_key(&group);
        if is_new && state.hardlinks.len() as u64 >= self.limits.hardlink_groups {
            return Err(CompileError::LimitExceeded("hard-link groups"));
        }
        state.hardlink_members = checked_add(state.hardlink_members, 1, "hard-link members")?;
        enforce(
            state.hardlink_members,
            self.limits.hardlink_members,
            "hard-link members",
        )?;
        let retained = hard_member_charge(metadata, content)?
            .checked_add(owned_path_charge(path)?)
            .ok_or(CompileError::LimitExceeded("working bytes"))?;
        let next = checked_add(state.working_bytes, retained, "working bytes")?;
        enforce(next, self.limits.working_bytes, "working bytes")?;
        state.working_bytes = next;
        state.maximum_working_bytes = state.maximum_working_bytes.max(next);
        let path = clone_path(path)?;
        state.hardlinks.entry(group).or_default().push(HardMember {
            path,
            metadata: metadata.clone(),
            content: content.clone(),
            charged_bytes: retained,
        });
        Ok(())
    }

    fn decode_limits(&self) -> DecodeLimits {
        DecodeLimits {
            maximum_bytes: self.limits.object_bytes,
            // Per-kind graph ceilings are charged by the compiler. The CBOR
            // preflight still needs to admit fixed schema arrays and arrays
            // such as ACLs whose ceiling is independent of directory fanout.
            maximum_collection_items: self.limits.object_bytes,
            maximum_total_items: self.limits.object_bytes.saturating_mul(2),
            maximum_byte_string_bytes: self.limits.object_bytes,
            maximum_text_bytes: 255,
            maximum_depth: 32,
        }
    }
}

/// Reports aggregate facts proven by one successful compilation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompileSummary {
    /// Expanded nodes, including the root.
    pub nodes: u64,
    /// Expanded directories, including the root.
    pub directories: u64,
    /// Aggregate logical regular-file bytes.
    pub logical_bytes: u64,
    /// Aggregate path-component bytes.
    pub name_bytes: u64,
    /// Aggregate xattr name and value bytes.
    pub xattr_bytes: u64,
    /// Aggregate ACL entries.
    pub acl_entries: u64,
    /// Aggregate sparse extents.
    pub extents: u64,
    /// Distinct hard-link groups.
    pub hardlink_groups: u64,
    /// Peak explicitly retained graph working bytes.
    pub maximum_working_bytes: u64,
}

/// Reports failure to compile an exact portable tree graph.
#[derive(Debug, thiserror::Error)]
pub enum CompileError<E: std::error::Error + 'static> {
    /// Exact object loading or verification failed.
    #[error(transparent)]
    Source(#[from] SourceError<E>),
    /// Canonical portable-object decoding failed.
    #[error(transparent)]
    Canonical(#[from] CanonicalCborError),
    /// A named graph-wide limit was exceeded.
    #[error("portable tree exceeds its {0} limit")]
    LimitExceeded(&'static str),
    /// A directory descriptor cycle was found on an expanded path.
    #[error("portable directory graph contains a cycle")]
    Cycle,
    /// The supplied source descriptor is not a portable tree.
    #[error("source descriptor is not a registered portable tree")]
    InvalidTreeDescriptor,
    /// The staged index is bound to a different source tree.
    #[error("structural-index builder is bound to a different source tree")]
    WrongIndexTarget,
    /// A required feature is not part of the closed portable-tree role.
    #[error("feature {0} is not supported for portable-tree semantics")]
    UnsupportedTreeFeature(String),
    /// Metadata requires a feature absent from the tree root.
    #[error("portable tree omits required feature {0}")]
    MissingFeature(&'static str),
    /// POSIX ACL structure disagrees with portable mode semantics.
    #[error("portable POSIX ACL is incomplete or inconsistent with mode bits")]
    InvalidAcl,
    /// A symlink requires an undeclared absolute or parent-escape feature.
    #[error("portable symlink target requires an undeclared feature")]
    InvalidSymlink,
    /// A hard-link group has inconsistent members or the wrong identifier.
    #[error("portable hard-link membership or identifier is invalid")]
    InvalidHardlink,
    /// A retained member path exceeds the portable path bound.
    #[error("expanded portable path exceeds its component bound")]
    InvalidPath,
    /// Structural-index staging failed.
    #[error(transparent)]
    Index(#[from] IndexError),
    /// Internal reserve/release arithmetic became inconsistent.
    #[error("compiler working-set accounting became inconsistent")]
    InternalAccounting,
}

#[derive(Default)]
struct WalkState {
    queue: VecDeque<Work>,
    hardlinks: BTreeMap<ObjectDigest, Vec<HardMember>>,
    nodes: u64,
    directories: u64,
    logical_bytes: u64,
    name_bytes: u64,
    symlink_bytes: u64,
    xattrs: u64,
    xattr_bytes: u64,
    acl_entries: u64,
    extents: u64,
    hardlink_members: u64,
    working_bytes: u64,
    maximum_working_bytes: u64,
}

struct Work {
    descriptor: ObjectDescriptor,
    parent: u64,
    depth: u32,
    sibling_ordinal: u32,
    name: Option<PathName>,
    path: Vec<PathName>,
    ancestors: Vec<ObjectDigest>,
    charged_bytes: u64,
}

struct HardMember {
    path: Vec<PathName>,
    metadata: FilesystemMetadata,
    content: ContentLayout,
    charged_bytes: u64,
}

fn validate_hardlinks<E>(
    state: &mut WalkState,
    maximum_working_bytes: u64,
) -> Result<(), CompileError<E>>
where
    E: std::error::Error + 'static,
{
    let temporary = state.hardlinks.values().try_fold(0_u64, |total, members| {
        let group_encoding = members.first().map_or(Ok(0), |member| {
            hard_member_charge(&member.metadata, &member.content)
        })?;
        members.iter().try_fold(
            total
                .checked_add(group_encoding)
                .ok_or(CompileError::LimitExceeded("working bytes"))?,
            |group_total, member| {
                group_total
                    .checked_add(owned_path_charge(&member.path)?)
                    .ok_or(CompileError::LimitExceeded("working bytes"))
            },
        )
    })?;
    let with_temporary = checked_add(state.working_bytes, temporary, "working bytes")?;
    enforce(with_temporary, maximum_working_bytes, "working bytes")?;
    state.maximum_working_bytes = state.maximum_working_bytes.max(with_temporary);

    for (claimed, members) in &mut state.hardlinks {
        members.sort_by(|left, right| compare_components(&left.path, &right.path));
        let first = members.first().ok_or(CompileError::InvalidHardlink)?;
        if members.len() < 2
            || members
                .iter()
                .any(|member| member.metadata != first.metadata || member.content != first.content)
            || members
                .windows(2)
                .any(|pair| compare_components(&pair[0].path, &pair[1].path) != Ordering::Less)
        {
            return Err(CompileError::InvalidHardlink);
        }
        let mut paths = Vec::new();
        paths
            .try_reserve_exact(members.len())
            .map_err(|_| CompileError::LimitExceeded("working bytes"))?;
        for member in members.iter() {
            paths.push(clone_relative_path(&member.path)?);
        }
        let actual = hardlink_group_digest(&paths, &first.metadata, &first.content)?;
        if &actual != claimed {
            return Err(CompileError::InvalidHardlink);
        }
        let _released = members.iter().try_fold(0_u64, |sum, member| {
            sum.checked_add(member.charged_bytes)
                .ok_or(CompileError::InternalAccounting)
        })?;
    }
    Ok(())
}

fn validate_acl_mode<E>(metadata: &FilesystemMetadata) -> Result<(), CompileError<E>>
where
    E: std::error::Error + 'static,
{
    let acl = metadata.acl().ok_or(CompileError::InvalidAcl)?;
    let mut user = None;
    let mut group = None;
    let mut mask = None;
    let mut other = None;
    let mut named = false;
    for entry in acl.entries() {
        match *entry {
            AclEntry::UserObject(value) => user = Some(value),
            AclEntry::NamedUser { .. } | AclEntry::NamedGroup { .. } => named = true,
            AclEntry::GroupObject(value) => group = Some(value),
            AclEntry::Mask(value) => mask = Some(value),
            AclEntry::Other(value) => other = Some(value),
        }
    }
    let mode = metadata.mode();
    if user != Some(((mode >> 6) & 7) as u8)
        || other != Some((mode & 7) as u8)
        || group.is_none()
        || (named && mask.is_none())
        || mask.or(group) != Some(((mode >> 3) & 7) as u8)
    {
        return Err(CompileError::InvalidAcl);
    }
    Ok(())
}

fn validate_symlink<E>(
    target: &[u8],
    path: &[PathName],
    features: &[FeatureRef],
) -> Result<(), CompileError<E>>
where
    E: std::error::Error + 'static,
{
    if target.first() == Some(&b'/') && !has_feature(features, ABSOLUTE_SYMLINK_FEATURE) {
        return Err(CompileError::InvalidSymlink);
    }
    if target.first() != Some(&b'/') {
        let mut depth = path.len().saturating_sub(1);
        for component in target.split(|byte| *byte == b'/') {
            match component {
                b"" | b"." => {}
                b".." if depth == 0 => {
                    if !has_feature(features, PARENT_SYMLINK_FEATURE) {
                        return Err(CompileError::InvalidSymlink);
                    }
                }
                b".." => depth -= 1,
                _ => depth = depth.saturating_add(1),
            }
        }
    }
    Ok(())
}

fn require_feature<E>(
    features: &[FeatureRef],
    namespace: &'static str,
) -> Result<(), CompileError<E>>
where
    E: std::error::Error + 'static,
{
    if has_feature(features, namespace) {
        Ok(())
    } else {
        Err(CompileError::MissingFeature(namespace))
    }
}

fn has_feature(features: &[FeatureRef], namespace: &str) -> bool {
    features.iter().any(|feature| {
        feature.namespace() == namespace && feature.major() == 1 && feature.minor() == 0
    })
}

fn validate_tree_features<E>(features: &[FeatureRef]) -> Result<u32, CompileError<E>>
where
    E: std::error::Error + 'static,
{
    let mut bits = 0_u32;
    for feature in features {
        let bit = match (feature.namespace(), feature.major(), feature.minor()) {
            (ACL_FEATURE, 1, 0) => FEATURE_ACL,
            (ABSOLUTE_SYMLINK_FEATURE, 1, 0) => FEATURE_ABSOLUTE_SYMLINK,
            (PARENT_SYMLINK_FEATURE, 1, 0) => FEATURE_PARENT_SYMLINK,
            _ => {
                return Err(CompileError::UnsupportedTreeFeature(
                    feature.namespace().to_owned(),
                ));
            }
        };
        bits |= bit;
    }
    Ok(bits)
}

fn compare_components(left: &[PathName], right: &[PathName]) -> Ordering {
    left.iter()
        .map(PathName::as_bytes)
        .cmp(right.iter().map(PathName::as_bytes))
}

fn work_charge<E>(
    path: &[PathName],
    appended_name: Option<&PathName>,
    ancestors: &[ObjectDigest],
) -> Result<u64, CompileError<E>>
where
    E: std::error::Error + 'static,
{
    let base = (std::mem::size_of::<Work>() as u64)
        .checked_add(512)
        .and_then(|value| value.checked_add(64))
        .and_then(|value| value.checked_add((ancestors.len() as u64).saturating_mul(32)))
        .ok_or(CompileError::LimitExceeded("working bytes"))?;
    let with_path = base
        .checked_add(owned_path_charge(path)?)
        .ok_or(CompileError::LimitExceeded("working bytes"))?;
    appended_name.map_or(Ok(with_path), |name| {
        with_path
            .checked_add(std::mem::size_of::<PathName>() as u64)
            .and_then(|value| value.checked_add(owned_name_charge(name)))
            .and_then(|value| value.checked_add(owned_name_charge(name)))
            .ok_or(CompileError::LimitExceeded("working bytes"))
    })
}

fn next_work_charge<E>(
    path: &[PathName],
    name: &PathName,
    ancestors: &[ObjectDigest],
) -> Result<u64, CompileError<E>>
where
    E: std::error::Error + 'static,
{
    work_charge(path, Some(name), ancestors)
}

fn hard_member_charge<E>(
    metadata: &FilesystemMetadata,
    content: &ContentLayout,
) -> Result<u64, CompileError<E>>
where
    E: std::error::Error + 'static,
{
    let mut bytes = (std::mem::size_of::<HardMember>() as u64)
        .checked_add(512)
        .ok_or(CompileError::LimitExceeded("working bytes"))?;
    for xattr in metadata.xattrs() {
        bytes = bytes
            .checked_add(192)
            .and_then(|value| {
                value.checked_add(((xattr.name().len() + xattr.value().len()) as u64) * 2)
            })
            .ok_or(CompileError::LimitExceeded("working bytes"))?;
    }
    if let Some(acl) = metadata.acl() {
        bytes = bytes
            .checked_add((acl.entries().len() as u64).saturating_mul(32))
            .ok_or(CompileError::LimitExceeded("working bytes"))?;
    }
    match content {
        ContentLayout::Whole { content } => {
            bytes = bytes
                .checked_add(192 + (content.media_type().as_str().len() as u64) * 2)
                .ok_or(CompileError::LimitExceeded("working bytes"))?;
        }
        ContentLayout::Sparse(sparse) => {
            for extent in sparse.extents() {
                bytes = bytes
                    .checked_add(256 + (extent.content().media_type().as_str().len() as u64) * 2)
                    .ok_or(CompileError::LimitExceeded("working bytes"))?;
            }
        }
    }
    Ok(bytes)
}

fn owned_name_charge(name: &PathName) -> u64 {
    128 + (name.as_bytes().len() as u64).saturating_mul(2)
}

fn owned_path_charge<E>(path: &[PathName]) -> Result<u64, CompileError<E>>
where
    E: std::error::Error + 'static,
{
    path.iter().try_fold(64_u64, |total, name| {
        total
            .checked_add(std::mem::size_of::<PathName>() as u64)
            .and_then(|value| value.checked_add(owned_name_charge(name)))
            .ok_or(CompileError::LimitExceeded("working bytes"))
    })
}

fn clone_relative_path<E>(path: &[PathName]) -> Result<RelativePath, CompileError<E>>
where
    E: std::error::Error + 'static,
{
    let components = clone_path(path)?;
    RelativePath::new(components).map_err(|_| CompileError::InvalidPath)
}

fn clone_path<E>(path: &[PathName]) -> Result<Vec<PathName>, CompileError<E>>
where
    E: std::error::Error + 'static,
{
    let mut components = Vec::new();
    components
        .try_reserve_exact(path.len())
        .map_err(|_| CompileError::LimitExceeded("working bytes"))?;
    for component in path {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(component.as_bytes().len())
            .map_err(|_| CompileError::LimitExceeded("working bytes"))?;
        bytes.extend_from_slice(component.as_bytes());
        components.push(PathName::new(bytes).map_err(|_| CompileError::InvalidPath)?);
    }
    Ok(components)
}

/// Reserves a conservative schema-specific upper bound before decoding.
///
/// Canonical CBOR can represent many small items whose Rust containers are
/// larger than their encoding. Sixty-four bytes per encoded byte plus fixed
/// parser scratch bounds every owned tree/directory representation used here;
/// the encoded object remains charged simultaneously.
fn object_reservation<E>(descriptor: &ObjectDescriptor) -> Result<u64, CompileError<E>>
where
    E: std::error::Error + 'static,
{
    let decoded = descriptor
        .encoded_size()
        .checked_mul(64)
        .and_then(|value| value.checked_add(4_096))
        .ok_or(CompileError::LimitExceeded("working bytes"))?;
    descriptor
        .encoded_size()
        .checked_add(decoded)
        .ok_or(CompileError::LimitExceeded("working bytes"))
}

fn tree_retained_charge<E>(
    root: &ObjectDescriptor,
    features: &[FeatureRef],
) -> Result<u64, CompileError<E>>
where
    E: std::error::Error + 'static,
{
    let root_bytes = 128_u64
        .checked_add(root.media_type().as_str().len() as u64)
        .ok_or(CompileError::LimitExceeded("working bytes"))?;
    features.iter().try_fold(root_bytes, |total, feature| {
        total
            .checked_add(64)
            .and_then(|value| value.checked_add(feature.namespace().len() as u64))
            .ok_or(CompileError::LimitExceeded("working bytes"))
    })
}

fn checked_add<E>(left: u64, right: u64, name: &'static str) -> Result<u64, CompileError<E>>
where
    E: std::error::Error + 'static,
{
    left.checked_add(right)
        .ok_or(CompileError::LimitExceeded(name))
}

fn push_index<E, W>(
    index: &mut StructuralIndexBuilder<W>,
    record: &IndexRecord<'_>,
    state: &mut WalkState,
    maximum_working_bytes: u64,
) -> Result<u64, CompileError<E>>
where
    E: std::error::Error + 'static,
    W: Write + Seek,
{
    let encoded_len = record_encoded_len(record)?;
    let reservation = byte_vector_charge(encoded_len)?;
    let current_index = index.retained_working_bytes()?;
    let next_index = index.retained_working_bytes_after_push()?;
    let retained_delta = next_index
        .checked_sub(current_index)
        .ok_or(CompileError::InternalAccounting)?;
    let with_retained = checked_add(state.working_bytes, retained_delta, "working bytes")?;
    let with_record = checked_add(with_retained, reservation, "working bytes")?;
    enforce(with_record, maximum_working_bytes, "working bytes")?;
    state.maximum_working_bytes = state.maximum_working_bytes.max(with_record);
    let external_working = state
        .working_bytes
        .checked_sub(current_index)
        .ok_or(CompileError::InternalAccounting)?;
    let pushed = index.push_with_external(record, external_working, maximum_working_bytes)?;
    state.maximum_working_bytes = state.maximum_working_bytes.max(pushed.peak_working_bytes);
    state.working_bytes = checked_add(
        external_working,
        pushed.retained_working_bytes,
        "working bytes",
    )?;
    Ok(pushed.record_id)
}

fn enforce<E>(value: u64, maximum: u64, name: &'static str) -> Result<(), CompileError<E>>
where
    E: std::error::Error + 'static,
{
    if value <= maximum {
        Ok(())
    } else {
        Err(CompileError::LimitExceeded(name))
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::io::{Cursor, Error as IoError, ErrorKind, SeekFrom};
    use std::sync::{Arc, Mutex};

    use aos_sandbox_core::MediaType;
    use aos_sandbox_core::format::{descriptor_for_bytes, encode_directory, encode_tree};
    use aos_sandbox_core::model::{
        Acl, Directory, DirectoryEntry, Extent, FileNode, SparseContent, SymlinkNode, Tree, Xattr,
    };

    use super::*;
    use crate::{INDEX_MEDIA_TYPE, IndexExpectation, IndexStaging, validate_index};

    #[derive(Default)]
    struct MemorySource(Vec<(ObjectDescriptor, Vec<u8>)>);

    #[derive(Clone)]
    struct SharedWriter {
        inner: Arc<Mutex<Cursor<Vec<u8>>>>,
        fail_after: Option<usize>,
    }

    impl Write for SharedWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let mut inner = self
                .inner
                .lock()
                .map_err(|_| IoError::other("poisoned test writer"))?;
            if let Some(limit) = self.fail_after {
                let position = inner.position() as usize;
                if position >= limit {
                    return Err(IoError::new(ErrorKind::WriteZero, "injected partial write"));
                }
                let allowed = bytes.len().min(limit - position);
                return inner.write(&bytes[..allowed]);
            }
            inner.write(bytes)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Seek for SharedWriter {
        fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
            self.inner
                .lock()
                .map_err(|_| IoError::other("poisoned test writer"))?
                .seek(position)
        }
    }

    impl MemorySource {
        fn insert(&mut self, media: &str, bytes: Vec<u8>) -> ObjectDescriptor {
            let media = MediaType::new(media)
                .unwrap_or_else(|error| panic!("test media type failed: {error}"));
            let descriptor = descriptor_for_bytes(media, &bytes);
            self.0.push((descriptor.clone(), bytes));
            descriptor
        }
    }

    impl ObjectSource for MemorySource {
        type Error = Infallible;
        type Reader = Cursor<Vec<u8>>;

        fn open(&mut self, descriptor: &ObjectDescriptor) -> Result<Self::Reader, Self::Error> {
            Ok(Cursor::new(
                self.0
                    .iter()
                    .find(|(candidate, _)| candidate == descriptor)
                    .map(|(_, bytes)| bytes.clone())
                    .unwrap_or_default(),
            ))
        }
    }

    fn metadata() -> FilesystemMetadata {
        FilesystemMetadata::new(0o755, 0, 0, 0, 0, Vec::new(), None)
            .unwrap_or_else(|error| panic!("metadata failed: {error}"))
    }

    fn fixture(entries: Vec<DirectoryEntry>) -> (MemorySource, ObjectDescriptor) {
        fixture_with_features(entries, Vec::new())
    }

    fn fixture_with_features(
        entries: Vec<DirectoryEntry>,
        features: Vec<FeatureRef>,
    ) -> (MemorySource, ObjectDescriptor) {
        let mut source = MemorySource::default();
        let directory = Directory::new(metadata(), entries)
            .unwrap_or_else(|error| panic!("directory failed: {error}"));
        let root = source.insert(
            "application/vnd.aos.sandbox.directory.v1+cbor",
            encode_directory(&directory),
        );
        let tree = Tree::new(root, features).unwrap_or_else(|error| panic!("tree failed: {error}"));
        let tree_descriptor = source.insert(
            "application/vnd.aos.sandbox.tree.v1+cbor",
            encode_tree(&tree),
        );
        (source, tree_descriptor)
    }

    fn compile_bytes(
        source: &mut MemorySource,
        tree: &ObjectDescriptor,
        limits: TreeCompileLimits,
    ) -> Result<(CompileSummary, Vec<u8>), CompileError<Infallible>> {
        let staging = IndexStaging::new(
            Cursor::new(Vec::new()),
            limits.index_bytes,
            limits.index_record_bytes,
        );
        let (summary, staged) =
            TreeCompiler::new(limits).compile(source, staging, tree, [9; 32])?;
        let (writer, _) = staged.into_parts();
        Ok((summary, writer.into_inner()))
    }

    #[test]
    fn compiler_streams_a_bounded_tree_into_a_valid_index() {
        let content = descriptor_for_bytes(
            MediaType::new("application/vnd.aos.sandbox.content.v1")
                .unwrap_or_else(|error| panic!("content media failed: {error}")),
            b"abc",
        );
        let file = Node::File(FileNode {
            metadata: metadata(),
            content: ContentLayout::whole(content),
            hardlink_group: None,
        });
        let entry = DirectoryEntry {
            name: PathName::new(b"file".to_vec())
                .unwrap_or_else(|error| panic!("name failed: {error}")),
            node: file,
        };
        let (mut source, tree) = fixture(vec![entry]);
        let staging = IndexStaging::new(Cursor::new(Vec::new()), 4096, 4096);
        let (summary, staged) = TreeCompiler::new(TreeCompileLimits::default())
            .compile(&mut source, staging, &tree, [9; 32])
            .unwrap_or_else(|error| panic!("compile failed: {error}"));
        assert_eq!(summary.nodes, 2);
        assert_eq!(summary.logical_bytes, 3);
        let (writer, expected_summary) = staged.into_parts();
        let index_media = MediaType::new(INDEX_MEDIA_TYPE)
            .unwrap_or_else(|error| panic!("index media failed: {error}"));
        let index_descriptor = descriptor_for_bytes(index_media, writer.get_ref());
        let tree_bytes = source
            .0
            .iter()
            .find(|(candidate, _)| candidate == &tree)
            .map(|(_, bytes)| bytes)
            .unwrap_or_else(|| panic!("tree missing"));
        let root = decode_tree(tree_bytes, DecodeLimits::default())
            .unwrap_or_else(|error| panic!("tree decode failed: {error}"))
            .root()
            .clone();
        let expectation = IndexExpectation {
            index: &index_descriptor,
            compiler_abi: [9; 32],
            tree: &tree,
            root: &root,
            tree_features: 0,
        };
        let validated = validate_index(writer.get_ref(), 4096, 1_048_576, &expectation)
            .unwrap_or_else(|error| panic!("validation failed: {error}"));
        assert_eq!(*validated.summary(), expected_summary);
    }

    #[test]
    fn compiler_index_limits_narrow_permissive_staging() {
        let (mut source, tree) = fixture(Vec::new());
        let staging = IndexStaging::new(Cursor::new(Vec::new()), u64::MAX, u64::MAX);
        let limits = TreeCompileLimits {
            index_bytes: 183,
            ..TreeCompileLimits::default()
        };
        assert!(matches!(
            TreeCompiler::new(limits).compile(&mut source, staging, &tree, [9; 32]),
            Err(CompileError::Index(IndexError::LimitExceeded))
        ));

        let staging = IndexStaging::new(Cursor::new(Vec::new()), u64::MAX, u64::MAX);
        let limits = TreeCompileLimits {
            index_record_bytes: 1,
            ..TreeCompileLimits::default()
        };
        assert!(matches!(
            TreeCompiler::new(limits).compile(&mut source, staging, &tree, [9; 32]),
            Err(CompileError::Index(IndexError::LimitExceeded))
        ));
    }

    #[test]
    fn mixed_and_multiple_directory_siblings_validate_independent_of_walk_order() {
        let mut source = MemorySource::default();
        let child_a_value = Directory::new(
            metadata(),
            vec![DirectoryEntry {
                name: PathName::new(b"aa".to_vec())
                    .unwrap_or_else(|error| panic!("name failed: {error}")),
                node: Node::Symlink(
                    SymlinkNode::new(metadata(), b"target-a".to_vec())
                        .unwrap_or_else(|error| panic!("symlink failed: {error}")),
                ),
            }],
        )
        .unwrap_or_else(|error| panic!("directory failed: {error}"));
        let child_b_value = Directory::new(
            metadata(),
            vec![DirectoryEntry {
                name: PathName::new(b"bb".to_vec())
                    .unwrap_or_else(|error| panic!("name failed: {error}")),
                node: Node::Symlink(
                    SymlinkNode::new(metadata(), b"target-b".to_vec())
                        .unwrap_or_else(|error| panic!("symlink failed: {error}")),
                ),
            }],
        )
        .unwrap_or_else(|error| panic!("directory failed: {error}"));
        let child_a = source.insert(
            "application/vnd.aos.sandbox.directory.v1+cbor",
            encode_directory(&child_a_value),
        );
        let child_b = source.insert(
            "application/vnd.aos.sandbox.directory.v1+cbor",
            encode_directory(&child_b_value),
        );
        let root = Directory::new(
            metadata(),
            vec![
                DirectoryEntry {
                    name: PathName::new(b"a".to_vec())
                        .unwrap_or_else(|error| panic!("name failed: {error}")),
                    node: Node::Directory(child_a),
                },
                DirectoryEntry {
                    name: PathName::new(b"b".to_vec())
                        .unwrap_or_else(|error| panic!("name failed: {error}")),
                    node: Node::Directory(child_b),
                },
            ],
        )
        .unwrap_or_else(|error| panic!("root failed: {error}"));
        let root_descriptor = source.insert(
            "application/vnd.aos.sandbox.directory.v1+cbor",
            encode_directory(&root),
        );
        let tree_value = Tree::new(root_descriptor.clone(), Vec::new())
            .unwrap_or_else(|error| panic!("tree failed: {error}"));
        let tree = source.insert(
            "application/vnd.aos.sandbox.tree.v1+cbor",
            encode_tree(&tree_value),
        );
        let (_, bytes) = compile_bytes(&mut source, &tree, TreeCompileLimits::default())
            .unwrap_or_else(|error| panic!("compile failed: {error}"));
        let index_media = MediaType::new(INDEX_MEDIA_TYPE)
            .unwrap_or_else(|error| panic!("index media failed: {error}"));
        let index_descriptor = descriptor_for_bytes(index_media, &bytes);
        let validated = validate_index(
            &bytes,
            TreeCompileLimits::default().index_bytes,
            u64::MAX,
            &IndexExpectation {
                index: &index_descriptor,
                compiler_abi: [9; 32],
                tree: &tree,
                root: &root_descriptor,
                tree_features: 0,
            },
        )
        .unwrap_or_else(|error| panic!("index validation failed: {error}"));
        let root_view = validated
            .root()
            .unwrap_or_else(|error| panic!("root failed: {error}"));
        assert_eq!(
            validated
                .nlink(&root_view)
                .unwrap_or_else(|error| panic!("root nlink failed: {error}")),
            4
        );
        let root_range = validated
            .directory_range(&root_view)
            .unwrap_or_else(|error| panic!("root range failed: {error}"));
        assert_eq!(root_range.len(), 2);
        for (ordinal, (directory_name, child_name)) in
            [(b"a".as_slice(), b"aa".as_slice()), (b"b", b"bb")]
                .into_iter()
                .enumerate()
        {
            let directory = root_range
                .get(ordinal as u64)
                .unwrap_or_else(|error| panic!("directory seek failed: {error}"))
                .unwrap_or_else(|| panic!("directory missing"))
                .into_node();
            assert_eq!(directory.name(), directory_name);
            assert_eq!(
                validated
                    .nlink(&directory)
                    .unwrap_or_else(|error| panic!("directory nlink failed: {error}")),
                2
            );
            let child = validated
                .directory_range(&directory)
                .unwrap_or_else(|error| panic!("child range failed: {error}"))
                .get(0)
                .unwrap_or_else(|error| panic!("child seek failed: {error}"))
                .unwrap_or_else(|| panic!("child missing"));
            assert_eq!(child.node().name(), child_name);
        }
    }

    #[test]
    fn expanded_node_limit_fails_before_a_third_record() {
        let content = descriptor_for_bytes(
            MediaType::new("application/vnd.aos.sandbox.content.v1")
                .unwrap_or_else(|error| panic!("content media failed: {error}")),
            b"",
        );
        let entries = [b"a".as_slice(), b"b".as_slice()]
            .into_iter()
            .map(|name| DirectoryEntry {
                name: PathName::new(name.to_vec())
                    .unwrap_or_else(|error| panic!("name failed: {error}")),
                node: Node::File(FileNode {
                    metadata: metadata(),
                    content: ContentLayout::whole(content.clone()),
                    hardlink_group: None,
                }),
            })
            .collect();
        let (mut source, tree) = fixture(entries);
        let limits = TreeCompileLimits {
            nodes: 2,
            ..TreeCompileLimits::default()
        };
        assert!(matches!(
            TreeCompiler::new(limits).compile(
                &mut source,
                IndexStaging::new(Cursor::new(Vec::new()), 4096, 4096),
                &tree,
                [1; 32],
            ),
            Err(CompileError::LimitExceeded("nodes"))
        ));
    }

    #[test]
    fn undeclared_absolute_symlink_feature_fails_closed() {
        let link = aos_sandbox_core::model::SymlinkNode::new(metadata(), b"/outside".to_vec())
            .unwrap_or_else(|error| panic!("symlink failed: {error}"));
        let entry = DirectoryEntry {
            name: PathName::new(b"link".to_vec())
                .unwrap_or_else(|error| panic!("name failed: {error}")),
            node: Node::Symlink(link),
        };
        let (mut source, tree) = fixture(vec![entry]);
        assert!(matches!(
            TreeCompiler::new(TreeCompileLimits::default()).compile(
                &mut source,
                IndexStaging::new(Cursor::new(Vec::new()), 4096, 4096),
                &tree,
                [1; 32],
            ),
            Err(CompileError::InvalidSymlink)
        ));
    }

    #[test]
    fn globally_registered_wrong_role_feature_is_rejected() {
        let feature = FeatureRef::new("aos.sandbox.runtime.linux-systemd", 1, 0)
            .unwrap_or_else(|error| panic!("feature failed: {error}"));
        let (mut source, tree) = fixture_with_features(Vec::new(), vec![feature]);
        let result = TreeCompiler::new(TreeCompileLimits::default()).compile(
            &mut source,
            IndexStaging::new(Cursor::new(Vec::new()), 4096, 4096),
            &tree,
            [1; 32],
        );
        assert!(matches!(
            result,
            Err(CompileError::UnsupportedTreeFeature(_))
        ));
    }

    #[test]
    fn failed_prefix_and_partial_writer_cannot_produce_staged_index() {
        let content = descriptor_for_bytes(
            MediaType::new("application/vnd.aos.sandbox.content.v1")
                .unwrap_or_else(|error| panic!("content media failed: {error}")),
            b"",
        );
        let entry = DirectoryEntry {
            name: PathName::new(b"file".to_vec())
                .unwrap_or_else(|error| panic!("name failed: {error}")),
            node: Node::File(FileNode {
                metadata: metadata(),
                content: ContentLayout::whole(content),
                hardlink_group: None,
            }),
        };
        let (source, tree) = fixture(vec![entry]);
        let retained = Arc::new(Mutex::new(Cursor::new(Vec::new())));
        let writer = SharedWriter {
            inner: retained.clone(),
            fail_after: None,
        };
        let limits = TreeCompileLimits {
            nodes: 1,
            ..TreeCompileLimits::default()
        };
        let result = TreeCompiler::new(limits).compile(
            &mut MemorySource(source.0.clone()),
            IndexStaging::new(writer, 4096, 4096),
            &tree,
            [1; 32],
        );
        assert!(matches!(result, Err(CompileError::LimitExceeded("nodes"))));
        let bytes = retained
            .lock()
            .unwrap_or_else(|error| panic!("lock failed: {error}"));
        assert!(
            bytes
                .get_ref()
                .get(..8)
                .is_some_and(|magic| magic == [0; 8])
        );
        drop(bytes);

        let partial = Arc::new(Mutex::new(Cursor::new(Vec::new())));
        let writer = SharedWriter {
            inner: partial.clone(),
            fail_after: Some(200),
        };
        let result = TreeCompiler::new(TreeCompileLimits::default()).compile(
            &mut MemorySource(source.0),
            IndexStaging::new(writer, 4096, 4096),
            &tree,
            [1; 32],
        );
        assert!(matches!(
            result,
            Err(CompileError::Index(IndexError::Io(_)))
        ));
        let bytes = partial
            .lock()
            .unwrap_or_else(|error| panic!("lock failed: {error}"));
        assert_eq!(bytes.get_ref().get(..8), Some(&[0; 8][..]));
    }

    #[test]
    fn compile_is_deterministic_and_declared_working_bound_is_exact() {
        let entries = [b"alpha".as_slice(), b"omega".as_slice()]
            .into_iter()
            .map(|name| DirectoryEntry {
                name: PathName::new(name.to_vec())
                    .unwrap_or_else(|error| panic!("name failed: {error}")),
                node: Node::Symlink(
                    aos_sandbox_core::model::SymlinkNode::new(metadata(), b"target".to_vec())
                        .unwrap_or_else(|error| panic!("symlink failed: {error}")),
                ),
            })
            .collect();
        let (source, tree) = fixture(entries);
        let (summary, first) = compile_bytes(
            &mut MemorySource(source.0.clone()),
            &tree,
            TreeCompileLimits::default(),
        )
        .unwrap_or_else(|error| panic!("first compile failed: {error}"));
        let exact = TreeCompileLimits {
            working_bytes: summary.maximum_working_bytes,
            ..TreeCompileLimits::default()
        };
        let mut reversed = source.0.clone();
        reversed.reverse();
        let (_, second) = compile_bytes(&mut MemorySource(reversed), &tree, exact)
            .unwrap_or_else(|error| panic!("exact-bound compile failed: {error}"));
        assert_eq!(first, second);

        let below = TreeCompileLimits {
            working_bytes: summary.maximum_working_bytes - 1,
            ..TreeCompileLimits::default()
        };
        assert!(matches!(
            compile_bytes(&mut MemorySource(source.0), &tree, below),
            Err(CompileError::LimitExceeded("working bytes"))
        ));
    }

    #[test]
    fn deep_path_container_overhead_is_part_of_the_working_bound() {
        let mut source = MemorySource::default();
        let mut child = source.insert(
            "application/vnd.aos.sandbox.directory.v1+cbor",
            encode_directory(
                &Directory::new(metadata(), Vec::new())
                    .unwrap_or_else(|error| panic!("leaf failed: {error}")),
            ),
        );
        for depth in (0..32).rev() {
            let name = format!("d{depth:02}").into_bytes();
            let directory = Directory::new(
                metadata(),
                vec![DirectoryEntry {
                    name: PathName::new(name)
                        .unwrap_or_else(|error| panic!("name failed: {error}")),
                    node: Node::Directory(child),
                }],
            )
            .unwrap_or_else(|error| panic!("directory failed: {error}"));
            child = source.insert(
                "application/vnd.aos.sandbox.directory.v1+cbor",
                encode_directory(&directory),
            );
        }
        let tree_value =
            Tree::new(child, Vec::new()).unwrap_or_else(|error| panic!("tree failed: {error}"));
        let tree = source.insert(
            "application/vnd.aos.sandbox.tree.v1+cbor",
            encode_tree(&tree_value),
        );
        let (summary, _) = compile_bytes(
            &mut MemorySource(source.0.clone()),
            &tree,
            TreeCompileLimits::default(),
        )
        .unwrap_or_else(|error| panic!("compile failed: {error}"));
        assert!(summary.maximum_working_bytes > 32 * std::mem::size_of::<PathName>() as u64);
        compile_bytes(
            &mut MemorySource(source.0.clone()),
            &tree,
            TreeCompileLimits {
                working_bytes: summary.maximum_working_bytes,
                ..TreeCompileLimits::default()
            },
        )
        .unwrap_or_else(|error| panic!("exact-bound compile failed: {error}"));
        assert!(matches!(
            compile_bytes(
                &mut source,
                &tree,
                TreeCompileLimits {
                    working_bytes: summary.maximum_working_bytes - 1,
                    ..TreeCompileLimits::default()
                },
            ),
            Err(CompileError::LimitExceeded("working bytes"))
        ));
    }

    #[test]
    fn retained_lookup_storage_is_combined_with_hardlink_validation_temporary() {
        let (source, tree) = fixture(Vec::new());
        let tree_bytes = source
            .0
            .iter()
            .find(|(candidate, _)| candidate == &tree)
            .map(|(_, bytes)| bytes)
            .unwrap_or_else(|| panic!("tree missing"));
        let root = decode_tree(tree_bytes, DecodeLimits::default())
            .unwrap_or_else(|error| panic!("tree decode failed: {error}"))
            .root()
            .clone();
        let mut index = StructuralIndexBuilder::new_v3(
            IndexStaging::new(Cursor::new(Vec::new()), 4096, 4096),
            [9; 32],
            tree,
            root.clone(),
            0,
        )
        .unwrap_or_else(|error| panic!("builder failed: {error}"));
        let mut state = WalkState {
            working_bytes: index
                .retained_working_bytes()
                .unwrap_or_else(|error| panic!("lookup charge failed: {error}")),
            ..WalkState::default()
        };
        let root_metadata = metadata();
        push_index::<Infallible, _>(
            &mut index,
            &IndexRecord {
                parent: u64::MAX,
                depth: 0,
                sibling_ordinal: 0,
                name: &[],
                metadata: &root_metadata,
                node: IndexNode::Directory { descriptor: &root },
            },
            &mut state,
            u64::MAX,
        )
        .unwrap_or_else(|error| panic!("root push failed: {error}"));
        push_index::<Infallible, _>(
            &mut index,
            &IndexRecord {
                parent: 0,
                depth: 1,
                sibling_ordinal: 0,
                name: b"prior",
                metadata: &root_metadata,
                node: IndexNode::Symlink { target: b"target" },
            },
            &mut state,
            u64::MAX,
        )
        .unwrap_or_else(|error| panic!("child push failed: {error}"));

        let hardlink_metadata = metadata();
        let content_descriptor = descriptor_for_bytes(
            MediaType::new("application/vnd.aos.sandbox.content.v1")
                .unwrap_or_else(|error| panic!("content media failed: {error}")),
            b"",
        );
        let content = ContentLayout::whole(content_descriptor);
        let paths = [b"a".as_slice(), b"b".as_slice()]
            .into_iter()
            .map(|name| {
                RelativePath::new(vec![
                    PathName::new(name.to_vec())
                        .unwrap_or_else(|error| panic!("name failed: {error}")),
                ])
                .unwrap_or_else(|error| panic!("path failed: {error}"))
            })
            .collect::<Vec<_>>();
        let group = hardlink_group_digest(&paths, &hardlink_metadata, &content)
            .unwrap_or_else(|error| panic!("group failed: {error}"));
        for path in &paths {
            TreeCompiler::new(TreeCompileLimits::default())
                .add_hardlink(
                    &mut state,
                    group,
                    path.components(),
                    &hardlink_metadata,
                    &content,
                )
                .unwrap_or_else(|error: CompileError<Infallible>| {
                    panic!("hard-link retention failed: {error}")
                });
        }
        let member_charge = hard_member_charge::<Infallible>(&hardlink_metadata, &content)
            .unwrap_or_else(|error| panic!("member charge failed: {error}"));
        let validation_temporary = member_charge
            + paths
                .iter()
                .map(|path| {
                    owned_path_charge::<Infallible>(path.components())
                        .unwrap_or_else(|error| panic!("path charge failed: {error}"))
                })
                .sum::<u64>();
        let lookup_retained = index
            .retained_working_bytes()
            .unwrap_or_else(|error| panic!("lookup charge failed: {error}"));
        let exact_validation_peak = state.working_bytes + validation_temporary;
        let below_exact = exact_validation_peak - 1;
        assert!(exact_validation_peak - lookup_retained <= below_exact);
        assert!(matches!(
            validate_hardlinks::<Infallible>(&mut state, below_exact),
            Err(CompileError::LimitExceeded("working bytes"))
        ));
    }

    #[test]
    fn depth_and_fanout_accept_exact_boundary_and_reject_next() {
        let mut source = MemorySource::default();
        let child = Directory::new(metadata(), Vec::new())
            .unwrap_or_else(|error| panic!("child directory failed: {error}"));
        let child_descriptor = source.insert(
            "application/vnd.aos.sandbox.directory.v1+cbor",
            encode_directory(&child),
        );
        let root = Directory::new(
            metadata(),
            vec![DirectoryEntry {
                name: PathName::new(b"child".to_vec())
                    .unwrap_or_else(|error| panic!("name failed: {error}")),
                node: Node::Directory(child_descriptor),
            }],
        )
        .unwrap_or_else(|error| panic!("root directory failed: {error}"));
        let root_descriptor = source.insert(
            "application/vnd.aos.sandbox.directory.v1+cbor",
            encode_directory(&root),
        );
        let tree_value = Tree::new(root_descriptor, Vec::new())
            .unwrap_or_else(|error| panic!("tree failed: {error}"));
        let tree = source.insert(
            "application/vnd.aos.sandbox.tree.v1+cbor",
            encode_tree(&tree_value),
        );
        let exact = TreeCompileLimits {
            depth: 1,
            directory_entries: 1,
            ..TreeCompileLimits::default()
        };
        compile_bytes(&mut MemorySource(source.0.clone()), &tree, exact)
            .unwrap_or_else(|error| panic!("exact limits should pass: {error}"));
        let shallow = TreeCompileLimits { depth: 0, ..exact };
        assert!(matches!(
            compile_bytes(&mut source, &tree, shallow),
            Err(CompileError::LimitExceeded("depth"))
        ));
    }

    #[test]
    fn aggregate_xattr_limit_is_charged_before_index_publication() {
        let xattr = Xattr::new(b"user.test".to_vec(), vec![7; 8])
            .unwrap_or_else(|error| panic!("xattr failed: {error}"));
        let metadata = FilesystemMetadata::new(0o644, 0, 0, 0, 0, vec![xattr], None)
            .unwrap_or_else(|error| panic!("metadata failed: {error}"));
        let content = descriptor_for_bytes(
            MediaType::new("application/vnd.aos.sandbox.content.v1")
                .unwrap_or_else(|error| panic!("content media failed: {error}")),
            b"",
        );
        let entry = DirectoryEntry {
            name: PathName::new(b"file".to_vec())
                .unwrap_or_else(|error| panic!("name failed: {error}")),
            node: Node::File(FileNode {
                metadata,
                content: ContentLayout::whole(content),
                hardlink_group: None,
            }),
        };
        let (source, tree) = fixture(vec![entry]);
        let exact = TreeCompileLimits {
            xattr_bytes: 17,
            xattrs: 1,
            ..TreeCompileLimits::default()
        };
        compile_bytes(&mut MemorySource(source.0.clone()), &tree, exact)
            .unwrap_or_else(|error| panic!("exact xattr bound should pass: {error}"));
        let below = TreeCompileLimits {
            xattr_bytes: 16,
            ..exact
        };
        assert!(matches!(
            compile_bytes(&mut MemorySource(source.0), &tree, below),
            Err(CompileError::LimitExceeded("xattr bytes"))
        ));
    }

    #[test]
    fn hardlink_claim_with_wrong_group_digest_is_rejected() {
        let content = descriptor_for_bytes(
            MediaType::new("application/vnd.aos.sandbox.content.v1")
                .unwrap_or_else(|error| panic!("content media failed: {error}")),
            b"same",
        );
        let entries = [b"a".as_slice(), b"b".as_slice()]
            .into_iter()
            .map(|name| DirectoryEntry {
                name: PathName::new(name.to_vec())
                    .unwrap_or_else(|error| panic!("name failed: {error}")),
                node: Node::File(FileNode {
                    metadata: metadata(),
                    content: ContentLayout::whole(content.clone()),
                    hardlink_group: Some(ObjectDigest::from_bytes([8; 32])),
                }),
            })
            .collect();
        let (mut source, tree) = fixture(entries);
        assert!(matches!(
            compile_bytes(&mut source, &tree, TreeCompileLimits::default()),
            Err(CompileError::InvalidHardlink)
        ));
    }

    #[test]
    fn ancestor_cycle_is_rejected_before_resolver_io() {
        let (mut source, tree) = fixture(Vec::new());
        let tree_bytes = source
            .0
            .iter()
            .find(|(descriptor, _)| descriptor == &tree)
            .map(|(_, bytes)| bytes.clone())
            .unwrap_or_else(|| panic!("tree bytes missing"));
        let root = decode_tree(&tree_bytes, DecodeLimits::default())
            .unwrap_or_else(|error| panic!("tree decode failed: {error}"))
            .root()
            .clone();
        let staging = IndexStaging::new(Cursor::new(Vec::new()), 4096, 4096);
        let mut builder = StructuralIndexBuilder::new_v3(staging, [1; 32], tree, root.clone(), 0)
            .unwrap_or_else(|error| panic!("builder failed: {error}"));
        let work = Work {
            descriptor: root.clone(),
            parent: u64::MAX,
            depth: 0,
            sibling_ordinal: 0,
            name: None,
            path: Vec::new(),
            ancestors: vec![root.digest()],
            charged_bytes: 0,
        };
        assert!(matches!(
            TreeCompiler::new(TreeCompileLimits::default()).visit_directory(
                &mut source,
                &mut builder,
                &[],
                work,
                &mut WalkState::default(),
            ),
            Err(CompileError::Cycle)
        ));
    }

    #[test]
    fn acl_and_extent_aggregate_limits_are_exact() {
        let acl = Acl::new(vec![
            AclEntry::UserObject(7),
            AclEntry::NamedUser {
                uid: 4,
                permissions: 5,
            },
            AclEntry::GroupObject(5),
            AclEntry::Mask(5),
            AclEntry::Other(0),
        ])
        .unwrap_or_else(|error| panic!("ACL failed: {error}"));
        let file_metadata = FilesystemMetadata::new(0o750, 0, 0, 0, 0, Vec::new(), Some(acl))
            .unwrap_or_else(|error| panic!("metadata failed: {error}"));
        let media = MediaType::new("application/vnd.aos.sandbox.content.v1")
            .unwrap_or_else(|error| panic!("content media failed: {error}"));
        let first = Extent::new(0, 2, descriptor_for_bytes(media.clone(), b"aa"))
            .unwrap_or_else(|error| panic!("extent failed: {error}"));
        let second = Extent::new(4, 2, descriptor_for_bytes(media, b"bb"))
            .unwrap_or_else(|error| panic!("extent failed: {error}"));
        let sparse = SparseContent::new(8, vec![first, second])
            .unwrap_or_else(|error| panic!("sparse content failed: {error}"));
        let entry = DirectoryEntry {
            name: PathName::new(b"file".to_vec())
                .unwrap_or_else(|error| panic!("name failed: {error}")),
            node: Node::File(FileNode {
                metadata: file_metadata,
                content: ContentLayout::Sparse(sparse),
                hardlink_group: None,
            }),
        };
        let feature = FeatureRef::new(ACL_FEATURE, 1, 0)
            .unwrap_or_else(|error| panic!("feature failed: {error}"));
        let (source, tree) = fixture_with_features(vec![entry], vec![feature]);
        let exact = TreeCompileLimits {
            acl_entries: 5,
            extents: 2,
            ..TreeCompileLimits::default()
        };
        compile_bytes(&mut MemorySource(source.0.clone()), &tree, exact)
            .unwrap_or_else(|error| panic!("exact limits should pass: {error}"));
        assert!(matches!(
            compile_bytes(
                &mut MemorySource(source.0.clone()),
                &tree,
                TreeCompileLimits {
                    acl_entries: 4,
                    ..exact
                },
            ),
            Err(CompileError::LimitExceeded("ACL entries"))
        ));
        assert!(matches!(
            compile_bytes(
                &mut MemorySource(source.0),
                &tree,
                TreeCompileLimits {
                    extents: 1,
                    ..exact
                },
            ),
            Err(CompileError::LimitExceeded("extents"))
        ));
    }
}
