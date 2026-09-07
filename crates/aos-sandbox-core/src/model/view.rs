//! Portable filesystem view and project-environment values.
//!
//! Views describe logical sources and presentation programs without choosing
//! a host path, mount mechanism, file descriptor, or node-local cache. Project
//! environments similarly commit to immutable descriptors and ordered logical
//! paths rather than host store locations or mutable package channels.

use serde::{Deserialize, Serialize};

use crate::{
    CacheDomainId, ExportId, FeatureRef, ObjectDescriptor, RelativePath, Revision, SandboxId,
};

const MAX_ENVIRONMENT_NAME_BYTES: usize = 4_096;
const MAX_ENVIRONMENT_VALUE_BYTES: usize = 1_048_576;

/// Reports an invalid portable view or environment value.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InvalidViewModel {
    /// A set-valued collection is not strictly ordered and unique.
    #[error("set-valued collection must be strictly ordered and unique")]
    SetNotCanonical,
    /// Two presentation actions can claim overlapping destination subtrees.
    #[error("view presentation destinations must not overlap")]
    OverlappingDestination,
    /// Source and consistency semantics cannot be realized together.
    #[error("view source and consistency class are incompatible")]
    IncompatibleConsistency,
    /// An environment variable name or value exceeds its portable bound.
    #[error("environment entry is outside its portable text bounds")]
    InvalidEnvironmentEntry,
    /// Environment entries are not strictly ordered by name.
    #[error("environment entries must be strictly ordered by name")]
    EnvironmentNotCanonical,
}

/// Selects one immutable or generation-fenced live view source.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum ViewSource {
    /// Resolves an immutable portable tree.
    ImmutableTree {
        /// Exact tree descriptor.
        tree: ObjectDescriptor,
    },
    /// Resolves one live export at an exact source generation.
    LiveExport {
        /// Sandbox that owns the export.
        owner_sandbox: SandboxId,
        /// Logical export identity.
        export: ExportId,
        /// Generation that fences source replacement.
        source_generation: Revision,
    },
}

/// Stores one ordered namespace-presentation instruction.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum PresentationAction {
    /// Maps a source subtree into a destination subtree.
    Include {
        /// Relative path beneath the source root.
        source_prefix: RelativePath,
        /// Relative path beneath the presented root.
        destination: RelativePath,
    },
    /// Removes one destination subtree from presentation.
    Exclude {
        /// Relative path beneath the presented root.
        destination: RelativePath,
    },
    /// Applies a registered metadata/presentation profile at a destination.
    Present {
        /// Relative path beneath the presented root.
        destination: RelativePath,
        /// Registered presentation semantics.
        presentation_profile: FeatureRef,
    },
}

impl PresentationAction {
    const fn destination(&self) -> &RelativePath {
        match self {
            Self::Include { destination, .. }
            | Self::Exclude { destination }
            | Self::Present { destination, .. } => destination,
        }
    }
}

/// Identifies a view's source-consistency contract.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ViewConsistency {
    /// The source is a fixed immutable tree.
    Immutable,
    /// The source is a live export on the consumer's assigned node.
    LocalLive,
    /// The source is mutable but fenced by an external exact version.
    ExternalVersioned,
}

/// Identifies the maximum mutation semantics a view can expose.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ViewMutation {
    /// Rejects all consumer mutation.
    ReadOnly,
    /// Writes directly to the mutable source.
    ReadWrite,
    /// Writes into a consumer-private delta over an immutable source.
    PrivateCow,
    /// Permits only append-style publication semantics.
    AppendOnly,
    /// Projects a protocol-defined service rather than ordinary file writes.
    Service,
}

/// Identifies the disclosure domain that may share cache backing and timing.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CacheDomainKind {
    /// Isolates backing and residency to one sandbox authority.
    Private,
    /// Allows sharing within one project.
    Project,
    /// Allows sharing among principals in an explicit trust domain.
    TrustDomain,
    /// Allows public cross-project sharing.
    Public,
}

/// Binds a cache disclosure class to its exact authority domain.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheDomain {
    kind: CacheDomainKind,
    domain_id: CacheDomainId,
}

impl CacheDomain {
    /// Constructs an explicit cache disclosure domain.
    #[must_use]
    pub const fn new(kind: CacheDomainKind, domain_id: CacheDomainId) -> Self {
        Self { kind, domain_id }
    }

    /// Returns the disclosure class.
    #[must_use]
    pub const fn kind(self) -> CacheDomainKind {
        self.kind
    }

    /// Returns the exact authority domain identity.
    #[must_use]
    pub const fn domain_id(self) -> CacheDomainId {
        self.domain_id
    }
}

/// Stores one portable filesystem view object.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct View {
    source: ViewSource,
    presentation: Vec<PresentationAction>,
    consistency: ViewConsistency,
    mutation: ViewMutation,
    identity_presentation: FeatureRef,
    disclosure: CacheDomain,
    required_features: Vec<FeatureRef>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ViewWire {
    source: ViewSource,
    presentation: Vec<PresentationAction>,
    consistency: ViewConsistency,
    mutation: ViewMutation,
    identity_presentation: FeatureRef,
    disclosure: CacheDomain,
    required_features: Vec<FeatureRef>,
}

impl<'de> Deserialize<'de> for View {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = ViewWire::deserialize(deserializer)?;
        Self::new(
            wire.source,
            wire.presentation,
            wire.consistency,
            wire.mutation,
            wire.identity_presentation,
            wire.disclosure,
            wire.required_features,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl View {
    /// Constructs a portable view with closed source/consistency semantics.
    ///
    /// # Errors
    ///
    /// Returns an error for an unordered feature set, overlapping presentation
    /// destinations, or incompatible source and consistency variants.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        source: ViewSource,
        presentation: Vec<PresentationAction>,
        consistency: ViewConsistency,
        mutation: ViewMutation,
        identity_presentation: FeatureRef,
        disclosure: CacheDomain,
        required_features: Vec<FeatureRef>,
    ) -> Result<Self, InvalidViewModel> {
        validate_features(&required_features)?;
        validate_destinations(&presentation)?;

        let compatible = matches!(
            (&source, consistency),
            (ViewSource::ImmutableTree { .. }, ViewConsistency::Immutable)
                | (ViewSource::LiveExport { .. }, ViewConsistency::LocalLive)
                | (
                    ViewSource::LiveExport { .. },
                    ViewConsistency::ExternalVersioned
                )
        );
        if !compatible {
            return Err(InvalidViewModel::IncompatibleConsistency);
        }

        Ok(Self {
            source,
            presentation,
            consistency,
            mutation,
            identity_presentation,
            disclosure,
            required_features,
        })
    }

    /// Returns the logical source.
    #[must_use]
    pub const fn source(&self) -> &ViewSource {
        &self.source
    }

    /// Returns the ordered presentation program.
    #[must_use]
    pub fn presentation(&self) -> &[PresentationAction] {
        &self.presentation
    }

    /// Returns the source-consistency contract.
    #[must_use]
    pub const fn consistency(&self) -> ViewConsistency {
        self.consistency
    }

    /// Returns the maximum permitted mutation semantics.
    #[must_use]
    pub const fn mutation(&self) -> ViewMutation {
        self.mutation
    }

    /// Returns the required identity-presentation profile.
    #[must_use]
    pub const fn identity_presentation(&self) -> &FeatureRef {
        &self.identity_presentation
    }

    /// Returns the cache disclosure domain.
    #[must_use]
    pub const fn disclosure(&self) -> CacheDomain {
        self.disclosure
    }

    /// Returns the exact required feature set.
    #[must_use]
    pub fn required_features(&self) -> &[FeatureRef] {
        &self.required_features
    }
}

/// Stores one UTF-8 environment variable assignment.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct EnvironmentEntry {
    name: String,
    value: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvironmentEntryWire {
    name: String,
    value: String,
}

impl<'de> Deserialize<'de> for EnvironmentEntry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = EnvironmentEntryWire::deserialize(deserializer)?;
        Self::new(wire.name, wire.value).map_err(serde::de::Error::custom)
    }
}

impl EnvironmentEntry {
    /// Constructs one bounded UTF-8 environment assignment.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidViewModel::InvalidEnvironmentEntry`] for an empty or
    /// oversized name, a NUL byte, `=`, or an oversized/NUL-containing value.
    pub fn new(name: String, value: String) -> Result<Self, InvalidViewModel> {
        if name.is_empty()
            || name.len() > MAX_ENVIRONMENT_NAME_BYTES
            || name.contains(['\0', '='])
            || value.len() > MAX_ENVIRONMENT_VALUE_BYTES
            || value.contains('\0')
        {
            return Err(InvalidViewModel::InvalidEnvironmentEntry);
        }
        Ok(Self { name, value })
    }

    /// Returns the variable name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the uninterpreted variable value.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}

/// Stores one immutable project environment generation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Environment {
    closure: Vec<ObjectDescriptor>,
    variables: Vec<EnvironmentEntry>,
    command_search_path: Vec<RelativePath>,
    required_features: Vec<FeatureRef>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvironmentWire {
    closure: Vec<ObjectDescriptor>,
    variables: Vec<EnvironmentEntry>,
    command_search_path: Vec<RelativePath>,
    required_features: Vec<FeatureRef>,
}

impl<'de> Deserialize<'de> for Environment {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = EnvironmentWire::deserialize(deserializer)?;
        Self::new(
            wire.closure,
            wire.variables,
            wire.command_search_path,
            wire.required_features,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl Environment {
    /// Constructs a portable environment with canonical set/map collections.
    ///
    /// # Errors
    ///
    /// Returns an error for duplicate or unordered closure descriptors,
    /// variables, or required features.
    pub fn new(
        closure: Vec<ObjectDescriptor>,
        variables: Vec<EnvironmentEntry>,
        command_search_path: Vec<RelativePath>,
        required_features: Vec<FeatureRef>,
    ) -> Result<Self, InvalidViewModel> {
        if !strictly_increasing(&closure) || !strictly_increasing(&required_features) {
            return Err(InvalidViewModel::SetNotCanonical);
        }
        if !variables
            .windows(2)
            .all(|pair| pair[0].name() < pair[1].name())
        {
            return Err(InvalidViewModel::EnvironmentNotCanonical);
        }
        Ok(Self {
            closure,
            variables,
            command_search_path,
            required_features,
        })
    }

    /// Returns the canonical immutable closure descriptor set.
    #[must_use]
    pub fn closure(&self) -> &[ObjectDescriptor] {
        &self.closure
    }

    /// Returns variable assignments in strict name order.
    #[must_use]
    pub fn variables(&self) -> &[EnvironmentEntry] {
        &self.variables
    }

    /// Returns the semantic command search sequence.
    #[must_use]
    pub fn command_search_path(&self) -> &[RelativePath] {
        &self.command_search_path
    }

    /// Returns the exact required feature set.
    #[must_use]
    pub fn required_features(&self) -> &[FeatureRef] {
        &self.required_features
    }
}

fn validate_features(features: &[FeatureRef]) -> Result<(), InvalidViewModel> {
    if strictly_increasing(features) {
        Ok(())
    } else {
        Err(InvalidViewModel::SetNotCanonical)
    }
}

fn strictly_increasing<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn validate_destinations(actions: &[PresentationAction]) -> Result<(), InvalidViewModel> {
    for (index, action) in actions.iter().enumerate() {
        let destination = action.destination();
        if actions[..index].iter().any(|prior| {
            prior.destination().contains(destination) || destination.contains(prior.destination())
        }) {
            return Err(InvalidViewModel::OverlappingDestination);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MediaType, ObjectDigest, PathName};

    fn descriptor(byte: u8) -> ObjectDescriptor {
        ObjectDescriptor::new(
            MediaType::new("application/vnd.aos.sandbox.tree.v1+cbor")
                .unwrap_or_else(|error| panic!("test media type failed: {error}")),
            ObjectDigest::from_bytes([byte; 32]),
            1,
        )
    }

    fn path(name: &[u8]) -> RelativePath {
        RelativePath::new(vec![
            PathName::new(name.to_vec())
                .unwrap_or_else(|error| panic!("test name failed: {error}")),
        ])
        .unwrap_or_else(|error| panic!("test path failed: {error}"))
    }

    fn feature() -> FeatureRef {
        FeatureRef::new("aos.sandbox.identity.posix32", 1, 0)
            .unwrap_or_else(|error| panic!("test feature failed: {error}"))
    }

    #[test]
    fn live_source_cannot_claim_immutable_consistency() {
        let result = View::new(
            ViewSource::LiveExport {
                owner_sandbox: SandboxId::from_bytes([1; 16]),
                export: ExportId::from_bytes([2; 16]),
                source_generation: Revision::new(1),
            },
            Vec::new(),
            ViewConsistency::Immutable,
            ViewMutation::ReadOnly,
            feature(),
            CacheDomain::new(CacheDomainKind::Private, CacheDomainId::from_bytes([3; 16])),
            Vec::new(),
        );

        assert_eq!(result, Err(InvalidViewModel::IncompatibleConsistency));
    }

    #[test]
    fn presentation_rejects_ancestor_overlap() {
        let actions = vec![
            PresentationAction::Exclude {
                destination: path(b"workspace"),
            },
            PresentationAction::Present {
                destination: RelativePath::new(vec![
                    PathName::new(b"workspace".to_vec())
                        .unwrap_or_else(|error| panic!("test name failed: {error}")),
                    PathName::new(b"src".to_vec())
                        .unwrap_or_else(|error| panic!("test name failed: {error}")),
                ])
                .unwrap_or_else(|error| panic!("test path failed: {error}")),
                presentation_profile: feature(),
            },
        ];

        let result = View::new(
            ViewSource::ImmutableTree {
                tree: descriptor(1),
            },
            actions,
            ViewConsistency::Immutable,
            ViewMutation::ReadOnly,
            feature(),
            CacheDomain::new(CacheDomainKind::Project, CacheDomainId::from_bytes([3; 16])),
            Vec::new(),
        );
        assert_eq!(result, Err(InvalidViewModel::OverlappingDestination));
    }

    #[test]
    fn environment_rejects_duplicate_variable_names() {
        let first = EnvironmentEntry::new("PATH".to_owned(), "bin".to_owned())
            .unwrap_or_else(|error| panic!("test entry failed: {error}"));
        let second = EnvironmentEntry::new("PATH".to_owned(), "tools".to_owned())
            .unwrap_or_else(|error| panic!("test entry failed: {error}"));

        assert_eq!(
            Environment::new(Vec::new(), vec![first, second], Vec::new(), Vec::new()),
            Err(InvalidViewModel::EnvironmentNotCanonical)
        );
    }

    #[test]
    fn environment_closure_is_a_canonical_set() {
        assert_eq!(
            Environment::new(
                vec![descriptor(2), descriptor(1)],
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
            Err(InvalidViewModel::SetNotCanonical)
        );
    }

    #[test]
    fn environment_entries_reject_shell_ambiguous_names() {
        assert_eq!(
            EnvironmentEntry::new("A=B".to_owned(), "value".to_owned()),
            Err(InvalidViewModel::InvalidEnvironmentEntry)
        );
    }
}
