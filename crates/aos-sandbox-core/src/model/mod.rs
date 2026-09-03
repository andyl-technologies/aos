//! Portable authority and content data models.
//!
//! These modules define validated semantic values for the portable v1 CDDL.
//! They intentionally do not define the canonical CBOR codec: [`crate`] users
//! cannot mistake a convenient Serde representation for the signed wire form.

pub mod policy;
pub mod snapshot;
pub mod spec;
pub mod tree;
pub mod view;

pub use policy::{
    ExplanationReason, ExplanationReasonCode, InvalidPolicyModel, Optimization, OptimizationKind,
    OptimizationProfile, Policy, PolicyViewAction, RevocationMode, RevocationPolicy,
};
pub use snapshot::{
    AttachmentSnapshot, ExternalDependency, InvalidSnapshotModel, OpaqueVersion, QuiesceEvidence,
    Receipt, RetentionClaim, Snapshot, SnapshotConsistency, SourceAssignment, StorageCheckpoint,
};
pub use spec::{
    IdentityProfile, InvalidSpecModel, Limit, LimitDimension, LimitValue, NetworkKind,
    NetworkProfile, ResourceProfile, SandboxSpec, UnmappableIdentityPolicy,
};
pub use tree::{
    Acl, AclEntry, ContentLayout, Delta, Directory, DirectoryEntry, Extent, FileNode,
    FilesystemMetadata, InvalidTreeModel, Node, SparseContent, SymlinkNode, Tree, Xattr,
};
pub use view::{
    CacheDomain, CacheDomainKind, Environment, EnvironmentEntry, InvalidViewModel,
    PresentationAction, View, ViewConsistency, ViewMutation, ViewSource,
};
