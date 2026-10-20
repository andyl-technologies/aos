//! Encodes untrusted original-authority, Guard and consumed-lineage evidence.
//!
//! These public records describe claims, not capabilities. Decoding never
//! creates original authority, a trusted Guard, or verified source lineage.
//! Physical ownership, current policy, signatures and exhaustive consumed
//! dependencies require independent private factories and backend evidence.
//! Existing local registrations and version-one import bytes remain unchanged.
//!
//! ```text
//! OriginalBootstrap = [1, original_id, ref_name, epoch, ordered_acl]
//! GuardSnapshot = {0: 1, 1: registration, 2: issuers, 3: roles,
//!                  4: configuration, 5: registry_inputs}
//! ```

mod cbor;
mod validation;
mod view_interpretation;

pub use view_interpretation::{ConsumedViewInterpretation, ViewInterpretationMode};

use super::{BackendBinding, PublicationError, RawDigest};
use crate::refs::{Locality, RefRecord};
use alloc::{string::String, vec::Vec};
use core::fmt;

/// Reports a canonical evidence encoding or represented consistency failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EvidenceError {
    /// Deterministic CBOR validation failed.
    Cbor(crate::cbor::Error),
    /// An embedded whole ref or signed commit has an invalid record shape.
    Record(crate::refs::RecordError),
    /// A backend binding violates its canonical publication schema.
    Binding(PublicationError),
    /// A chunk profile violates registered FastCDC constraints.
    Profile(crate::chunking::ProfileError),
    /// A canonical property or occurrence path is malformed.
    Tree(crate::tree_format::Error),
    /// A behavioral property value violates its registered semantics.
    Property(crate::properties::Error),
    /// A signed commit cannot be identified under the registered profile.
    Identity(crate::refs::CommitIdentityError),
    /// A field violates its registered schema.
    Schema,
    /// Represented fields or repeated evidence contradict one another.
    Contradiction,
    /// A claimed semantic revision has no registered interpretation.
    UnsupportedRevision,
}

impl fmt::Display for EvidenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cbor(error) => error.fmt(formatter),
            Self::Record(error) => error.fmt(formatter),
            Self::Binding(error) => error.fmt(formatter),
            Self::Profile(error) => error.fmt(formatter),
            Self::Tree(error) => error.fmt(formatter),
            Self::Property(error) => error.fmt(formatter),
            Self::Identity(error) => error.fmt(formatter),
            Self::Schema => formatter.write_str("evidence violates its registered schema"),
            Self::Contradiction => formatter.write_str("represented evidence is contradictory"),
            Self::UnsupportedRevision => {
                formatter.write_str("unregistered evidence semantics revision")
            }
        }
    }
}

impl core::error::Error for EvidenceError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Cbor(error) => Some(error),
            Self::Record(error) => Some(error),
            Self::Binding(error) => Some(error),
            Self::Profile(error) => Some(error),
            Self::Tree(error) => Some(error),
            Self::Property(error) => Some(error),
            Self::Identity(error) => Some(error),
            _ => None,
        }
    }
}

macro_rules! from_error {
    ($($source:ty => $variant:ident),+ $(,)?) => {$(
        impl From<$source> for EvidenceError {
            fn from(error: $source) -> Self { Self::$variant(error) }
        }
    )+};
}

from_error!(crate::cbor::Error => Cbor, crate::refs::RecordError => Record,
    PublicationError => Binding, crate::chunking::ProfileError => Profile,
    crate::tree_format::Error => Tree, crate::properties::Error => Property,
    crate::refs::CommitIdentityError => Identity);

/// Describes the unchanged nine-element local original registration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalOriginalRegistration {
    /// Claimed original-authority identity.
    pub original_id: RawDigest,
    /// Claimed normalized absolute bucket-root bytes.
    pub root: Vec<u8>,
    /// Claimed physical disclosure domain.
    pub domain: String,
    /// Claimed actual root device.
    pub root_device: u64,
    /// Claimed actual root inode.
    pub root_inode: u64,
    /// Claimed stable coordination device.
    pub coordination_device: u64,
    /// Claimed stable coordination inode.
    pub coordination_inode: u64,
    /// Claimed normalized absolute protected original-control path.
    pub control: Vec<u8>,
}

/// Describes a remote original registration without local inode placeholders.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteOriginalRegistration {
    /// Claimed protected original-authority identity.
    pub original_id: RawDigest,
    /// Claimed physical disclosure domain.
    pub domain: String,
    /// Exact remote binding; local case zero is forbidden here.
    pub binding: BackendBinding,
    /// Exact protected original-control namespace bytes.
    pub control: Vec<u8>,
}

/// Preserves the local and explicitly remote physical-registration union.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PhysicalRegistration {
    /// The existing local version-one nine-element registration.
    Local(LocalOriginalRegistration),
    /// The explicitly remote case-two five-element registration.
    Remote(RemoteOriginalRegistration),
}

/// Carries an ordered baseline grant, without authenticating its principal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityGrant {
    /// Nonempty exact principal or group name.
    pub principal: String,
    /// Registered read/fork/commit/tag/admin bitmask, including zero.
    pub verbs: u8,
}

/// Preserves configured grant order and repetitions exactly.
pub type AuthorityAcl = Vec<AuthorityGrant>;

/// Records the claimed initial ACL for an original authority and ref epoch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OriginalBootstrap {
    /// Claimed original-authority identity.
    pub original_id: RawDigest,
    /// Complete canonical ref name.
    pub ref_name: String,
    /// Original writer epoch.
    pub epoch: u64,
    /// Ordered baseline ACL, with repeated grants preserved.
    pub acl: AuthorityAcl,
}

/// Records the claimed association of a signed commit with its original owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OriginalAssociation {
    /// Domain-separated signed commit identity.
    pub commit: [u8; 32],
    /// Claimed original-authority identity.
    pub original_id: RawDigest,
    /// Exact original ref name.
    pub ref_name: String,
    /// Original writer epoch.
    pub epoch: u64,
}

/// Distinguishes the unchanged local import from the explicit binding union.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImportVersion {
    /// Version one admits only the existing local registration.
    LocalV1,
    /// Version two admits the explicitly registered physical-binding union.
    PhysicalV2,
}

/// Carries claimed retained source registration, baseline and association.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OriginalImport {
    /// Explicit encoding version; version one never admits remote bindings.
    pub version: ImportVersion,
    /// Claimed retained source registration.
    pub registration: PhysicalRegistration,
    /// Exact ordered source baseline.
    pub bootstrap: OriginalBootstrap,
    /// Claimed signed-commit association.
    pub association: OriginalAssociation,
}

/// Binds an exact retained import record to source and destination identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OriginalImportBinding {
    /// Domain-separated imported signed commit identity.
    pub commit: [u8; 32],
    /// Claimed source original-authority identity.
    pub source: RawDigest,
    /// Claimed destination original-authority identity.
    pub destination: RawDigest,
    /// Raw BLAKE3 of the exact canonical import bytes.
    pub import_digest: RawDigest,
}

/// Carries a historical issuer key and its optional retirement time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuerRow {
    /// Exact issuer identifier.
    pub issuer: String,
    /// Exact key identifier within that issuer.
    pub key_id: String,
    /// Claimed public Ed25519 key bytes.
    pub public_key: [u8; 32],
    /// Retirement time, or explicit absence of retirement.
    pub retired_at: Option<u64>,
}

/// Carries a repository-scoped disclosure role and validity interval.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisclosureRow {
    /// Lowercase 64-hex claimed original-authority repository identity.
    pub repository: String,
    /// Exact canonical disclosure-domain label.
    pub domain: String,
    /// Claimed disclosure public key bytes.
    pub public_key: [u8; 32],
    /// Inclusive start of validity.
    pub not_before: u64,
    /// Exclusive validity end; absence leaves the interval open.
    pub not_after: Option<u64>,
}

/// Carries untrusted retained public trust evidence for an exact import.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OriginalImportTrust {
    /// Raw digest of exact canonical import bytes.
    pub import_digest: RawDigest,
    /// Claimed source original-authority identity.
    pub source: RawDigest,
    /// Claimed destination original-authority identity.
    pub destination: RawDigest,
    /// Issuer rows sorted uniquely by exact issuer and key identifier.
    pub issuers: Vec<IssuerRow>,
    /// Disclosure rows sorted uniquely by repository/domain/key/start.
    pub disclosures: Vec<DisclosureRow>,
}

/// Stores only the six canonical seeded FastCDC inputs, without derived tables.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SeededChunkProfile {
    /// Minimum plaintext chunk size.
    pub minimum: u64,
    /// Target plaintext chunk size.
    pub target: u64,
    /// Maximum plaintext chunk size.
    pub maximum: u64,
    /// Registered effective mask span, exactly 48.
    pub window: u8,
    /// Normalization level, subject to registered mask constraints.
    pub normalization: u8,
    /// Exact seed from which the gear table and masks are recomputed.
    pub seed: [u8; 32],
}

/// Carries a claimed complete Guard configuration, not trusted policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedGuardConfig {
    /// Exact store expression name.
    pub store_name: String,
    /// Private-domain encoding hint, never immutable ownership evidence.
    pub private_domain_hint: String,
    /// Complete configured locality, preserving absent labels.
    pub home: Locality,
    /// Ordered new-authoring baseline, never a historical baseline substitute.
    pub initial_acl: AuthorityAcl,
    /// Minimum size, equal to the seeded profile's minimum.
    pub minimum_chunk_size: u64,
    /// Claimed checked physical storage domain.
    pub storage_domain: String,
    /// Registered selected chunk profile name.
    pub chunk_profile_name: String,
    /// Six exact seeded profile parameters.
    pub chunk_profile: SeededChunkProfile,
    /// Optional policy authority, preserving null separately from text.
    pub policy_authority: Option<String>,
}

/// Carries the registered interpretation revisions and exact name fences.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfiguredRegistryInputs {
    /// Property behavior and default semantics revision.
    pub property_revision: u64,
    /// Complete behavioral names, sorted uniquely by unsigned UTF-8 bytes.
    pub behavioral_properties: Vec<String>,
    /// Attribute registry revision.
    pub attribute_revision: u64,
    /// Trust-selector semantics revision.
    pub selector_revision: u64,
    /// Tree format interpretation revision.
    pub tree_revision: u64,
    /// FastCDC/gear/mask semantics revision.
    pub chunk_revision: u64,
    /// Exact identity profile, currently terrane-v1.
    pub identity_profile: String,
    /// Inert later names, sorted uniquely and disjoint from behavioral names.
    pub later_properties: Vec<String>,
}

/// Carries an untrusted complete immutable Guard snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuardSnapshot {
    /// Claimed actual original registration.
    pub registration: PhysicalRegistration,
    /// Exact historical issuer rows.
    pub issuers: Vec<IssuerRow>,
    /// Exact historical disclosure rows.
    pub disclosures: Vec<DisclosureRow>,
    /// Claimed complete configured policy.
    pub configuration: TrustedGuardConfig,
    /// Exact registered semantic interpretation inputs.
    pub registries: ConfiguredRegistryInputs,
}

/// Identifies the registered original-control record carried by a pin.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ControlKind {
    /// Physical original registration.
    Registration,
    /// Original ordered bootstrap ACL.
    Bootstrap,
    /// Original signed commit association.
    Association,
    /// Exact original import record.
    Import,
    /// Exact source/destination import binding.
    ImportBinding,
    /// Retained public import trust.
    ImportTrust,
}

/// Carries one claimed actually consumed original-control dependency.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequiredControlPin {
    /// Registered original-control record kind.
    pub kind: ControlKind,
    /// Claimed actual physical owner of the retained record.
    pub owner: PhysicalRegistration,
    /// Exact registered relative original-control key.
    pub key: String,
    /// Raw digest of exact canonical control bytes.
    pub digest: RawDigest,
}

/// Preserves one canonical root-property layer and its graft-local overrides.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsumedRootLayer {
    /// Exact canonical property-map bytes for the ancestor or occurrence root.
    pub properties: Vec<u8>,
    /// Exact canonical property-map bytes for that root's graft overrides.
    pub overrides: Vec<u8>,
}

/// Carries one full absolute root occurrence and its ancestor-first layers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsumedRootPolicy {
    /// Domain-separated TreeNode identity of this root occurrence.
    pub root: [u8; 32],
    /// Exact absolute occurrence path; distinct paths retain repeated roots.
    pub path: Vec<u8>,
    /// Nonempty ancestor-first policy layers.
    pub layers: Vec<ConsumedRootLayer>,
}

/// Carries claimed root-policy occurrences consumed from one signed view.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsumedViewPolicy {
    /// Domain-separated signed view commit identity.
    pub view: [u8; 32],
    /// Claimed independently resolved default disclosure domain.
    pub default_domain: String,
    /// Exact root occurrences, preserving order and repeated root identities.
    pub roots: Vec<ConsumedRootPolicy>,
}

/// Carries a claimed exhaustive summary of privately consumed lineage evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LineageUsedInputs {
    /// Claimed consumed issuer rows.
    pub issuers: Vec<IssuerRow>,
    /// Claimed consumed disclosure rows.
    pub disclosures: Vec<DisclosureRow>,
    /// Exact canonical pins, which must equal the enclosing lineage's pins.
    pub controls: Vec<RequiredControlPin>,
    /// Registered semantic interpretation inputs.
    pub registries: ConfiguredRegistryInputs,
    /// Claimed complete current configuration.
    pub configuration: TrustedGuardConfig,
    /// Claimed actually consumed signed views and root-policy occurrences.
    pub views: Vec<ConsumedViewPolicy>,
    /// Optional exact per-view interpretation data; absence never means Legacy.
    ///
    /// This ordinary claim grants no cold-fork, source-carry or current authority.
    pub view_interpretations: Option<Vec<ConsumedViewInterpretation>>,
}

/// Carries canonical source evidence without creating verified source lineage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckedLineage {
    /// Exact full selected source ref name.
    pub source_name: String,
    /// Exact whole source ref, including its candidate selector.
    pub source: RefRecord,
    /// Domain-separated signed commit identity, equal to source.commit.
    pub commit_id: [u8; 32],
    /// Exact canonical signed Commit bytes.
    pub commit_bytes: Vec<u8>,
    /// Raw digest of a separately checked immutable Guard snapshot.
    pub guard_digest: RawDigest,
    /// Claimed qualified availability-loss generation.
    pub loss_generation: u64,
    /// Exact canonical consumed control pins.
    pub controls: Vec<RequiredControlPin>,
    /// Claimed actual original binding, never original-authority capability.
    pub original: PhysicalRegistration,
    /// Claimed exhaustive privately consumed dependencies.
    pub used: LineageUsedInputs,
}
