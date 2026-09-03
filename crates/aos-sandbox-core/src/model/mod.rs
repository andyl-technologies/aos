//! Portable authority and content data models.
//!
//! These modules define validated semantic values for the portable v1 CDDL.
//! They intentionally do not define the canonical CBOR codec: [`crate`] users
//! cannot mistake a convenient Serde representation for the signed wire form.

pub mod tree;
pub mod view;

pub use tree::{
    Acl, AclEntry, ContentLayout, Delta, Directory, DirectoryEntry, Extent, FileNode,
    FilesystemMetadata, InvalidTreeModel, Node, SparseContent, SymlinkNode, Tree, Xattr,
};
pub use view::{
    CacheDomain, CacheDomainKind, Environment, EnvironmentEntry, InvalidViewModel,
    PresentationAction, View, ViewConsistency, ViewMutation, ViewSource,
};
