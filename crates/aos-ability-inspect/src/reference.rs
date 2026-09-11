//! Checked public-package graphs for Hub, CLI, and editor inspection.
//!
//! A reference input wraps one [`PackageAbilityReference`] that its caller
//! obtained through an authenticated package or registry path. Checking proves
//! canonical identity and supported semantics; it deliberately does not claim
//! deployment authorization, provider availability, or live observation.
//!
//! ```json
//! {
//!   "schema": "aos.ability.reference-inspection-input/v1",
//!   "required_features": [],
//!   "reference": { "schema": "aos.package-ability-reference/v1" }
//! }
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};

use aos_ability_model::{ABILITY_LIMITS_V1, RequiredFeature};
use aos_contract::Sha256Digest;
use aos_contract::limits::JsonLimits;
use aos_doc_model::{
    MAX_ABILITY_REFERENCE_BYTES, PackageAbilityReference, ability_reference_supported_features,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::query::select_graph;
use crate::{
    Direction, GraphQuery, GraphQueryError, InspectionEdge, InspectionNode, InspectionRelation,
    NodeKey,
};

/// Exact schema discriminator for portable public-reference inspection input.
pub const REFERENCE_INSPECTION_INPUT_SCHEMA: &str = "aos.ability.reference-inspection-input/v1";

/// Maximum canonical bytes accepted for one public-reference inspection input.
pub const REFERENCE_INSPECTION_INPUT_MAX_BYTES: usize = MAX_ABILITY_REFERENCE_BYTES + 4 * 1024;

/// Exact schema discriminator for a complete checked public-reference graph.
pub const REFERENCE_INSPECTION_VIEW_SCHEMA: &str = "aos.ability.reference-inspection-view/v1";

/// Maximum canonical bytes emitted for one complete public-reference graph.
pub const REFERENCE_INSPECTION_VIEW_MAX_BYTES: usize =
    REFERENCE_INSPECTION_INPUT_MAX_BYTES.saturating_mul(2);

/// Exact schema discriminator for a bounded public-reference graph slice.
pub const REFERENCE_GRAPH_SLICE_SCHEMA: &str = "aos.ability.reference-inspection-slice/v1";

/// Carries one canonical public package reference into the shared inspector.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReferenceInspectionInput {
    schema: String,
    required_features: Vec<RequiredFeature>,
    reference: PackageAbilityReference,
}

/// Retains the checked input identity and whether a caller matched it externally.
#[derive(Clone, Debug)]
pub struct CheckedReferenceInspection {
    input: ReferenceInspectionInput,
    digest: Sha256Digest,
    externally_anchored: bool,
}

/// States what established the exact public-reference input identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ReferenceInspectionAnchor {
    /// The canonical reference was checked without an independent commitment.
    UnanchoredReference {
        /// Identifies the exact canonical reference-inspection input bytes.
        digest: Sha256Digest,
    },
    /// The checked input matched an independently supplied commitment.
    ExternallyAnchoredReference {
        /// Identifies the exact canonical reference-inspection input bytes.
        digest: Sha256Digest,
    },
}

/// Defines the only disclosure class carried by a public-reference graph.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReferenceInspectionDisclosure {
    /// Contains package-authored public contracts and no deployment values.
    PublicPackageContract,
}

/// Identifies a stable limitation on conclusions drawn from a public reference.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReferenceInspectionDiagnosticCode {
    /// The reference does not establish deployment authorization.
    DeploymentAuthorizationNotEvaluated,
    /// Conditional requirements have not been evaluated for an environment.
    ConditionalRequirementsNotEvaluated,
    /// No runtime provider or resource availability was observed.
    RuntimeAvailabilityNotObserved,
}

/// Describes one stable public-reference limitation for every frontend.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReferenceInspectionDiagnostic {
    /// Identifies the limitation without parsing prose.
    pub code: ReferenceInspectionDiagnosticCode,
    /// Explains the limitation for a human reader.
    pub message: String,
}

/// Owns the deterministic checked graph of one public package reference.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReferenceInspectionView {
    schema: String,
    required_features: Vec<RequiredFeature>,
    anchor: ReferenceInspectionAnchor,
    disclosure: ReferenceInspectionDisclosure,
    diagnostics: Vec<ReferenceInspectionDiagnostic>,
    nodes: Vec<InspectionNode>,
    edges: Vec<InspectionEdge>,
}

/// Owns one bounded query result over a checked public package reference.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReferenceGraphSlice {
    schema: String,
    required_features: Vec<RequiredFeature>,
    anchor: ReferenceInspectionAnchor,
    disclosure: ReferenceInspectionDisclosure,
    diagnostics: Vec<ReferenceInspectionDiagnostic>,
    roots: Vec<NodeKey>,
    direction: Direction,
    #[serde(skip_serializing_if = "Option::is_none")]
    after: Option<NodeKey>,
    max_depth: usize,
    max_nodes: usize,
    truncated: bool,
    nodes: Vec<InspectionNode>,
    edges: Vec<InspectionEdge>,
}

/// Reports why public-reference inspection input could not be checked or projected.
#[derive(Debug, Error)]
pub enum ReferenceInspectionError {
    /// Bounded strict JSON decoding failed.
    #[error("reference inspection input decoding failed: {0}")]
    Decode(String),
    /// Canonical JSON encoding failed.
    #[error("reference inspection encoding failed: {0}")]
    Encode(String),
    /// The input or output exceeds its version-1 byte bound.
    #[error("reference inspection document exceeds its encoded byte limit")]
    EncodedSizeLimit,
    /// The bytes are valid JSON but are not their canonical representation.
    #[error("reference inspection input is not canonically encoded")]
    NoncanonicalEncoding,
    /// The input schema discriminator is unsupported.
    #[error("reference inspection input has an unsupported schema discriminator")]
    UnsupportedSchema,
    /// Version 1 does not support optional input feature semantics.
    #[error("reference inspection input requires unsupported feature semantics")]
    UnsupportedFeatures,
    /// The nested package reference is invalid or uses unsupported semantics.
    #[error("reference inspection contains an invalid package reference: {0}")]
    InvalidReference(String),
    /// An independent commitment does not identify these exact canonical bytes.
    #[error("reference inspection input does not match the expected digest")]
    DigestMismatch,
    /// The projected view exceeds the shared graph item bound.
    #[error("reference inspection view exceeds its node or edge count limit")]
    ItemLimit,
    /// An exact interface key resolves to inconsistent public documents.
    #[error("reference inspection contains inconsistent documents for one interface key")]
    InconsistentInterface,
    /// Bounded graph evaluation failed.
    #[error(transparent)]
    Query(#[from] GraphQueryError),
}

impl ReferenceInspectionInput {
    /// Wraps one public package reference for portable inspection.
    ///
    /// # Errors
    ///
    /// Returns an error if the package reference is invalid or requires
    /// unsupported reference or interface semantics.
    pub fn new(reference: PackageAbilityReference) -> Result<Self, ReferenceInspectionError> {
        let input = Self {
            schema: REFERENCE_INSPECTION_INPUT_SCHEMA.to_string(),
            required_features: Vec::new(),
            reference,
        };
        input.validate()?;
        Ok(input)
    }

    /// Decodes one strictly bounded canonical public-reference input.
    ///
    /// # Errors
    ///
    /// Returns an error for oversized, malformed, noncanonical, unsupported,
    /// or semantically invalid input.
    pub fn decode(bytes: &[u8]) -> Result<Self, ReferenceInspectionError> {
        if bytes.len() > REFERENCE_INSPECTION_INPUT_MAX_BYTES {
            return Err(ReferenceInspectionError::EncodedSizeLimit);
        }
        let input = input_limits()
            .decode::<Self>(bytes, REFERENCE_INSPECTION_INPUT_SCHEMA)
            .map_err(|error| ReferenceInspectionError::Decode(error.to_string()))?;
        input.validate()?;
        if input.canonical_bytes()? != bytes {
            return Err(ReferenceInspectionError::NoncanonicalEncoding);
        }
        Ok(input)
    }

    /// Encodes this input as bounded canonical JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if the input is invalid, too large, or cannot be encoded.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ReferenceInspectionError> {
        self.validate()?;
        bounded_canonical_bytes(self, REFERENCE_INSPECTION_INPUT_MAX_BYTES)
    }

    /// Checks semantic support and optionally matches an external byte commitment.
    ///
    /// # Errors
    ///
    /// Returns an error if validation fails or `expected_digest` does not match
    /// the exact canonical input bytes.
    pub fn check(
        self,
        expected_digest: Option<Sha256Digest>,
    ) -> Result<CheckedReferenceInspection, ReferenceInspectionError> {
        let bytes = self.canonical_bytes()?;
        let digest = Sha256Digest::of_bytes(&bytes);
        if expected_digest.is_some_and(|expected| expected != digest) {
            return Err(ReferenceInspectionError::DigestMismatch);
        }
        Ok(CheckedReferenceInspection {
            input: self,
            digest,
            externally_anchored: expected_digest.is_some(),
        })
    }

    /// Returns the nested public package reference.
    #[must_use]
    pub const fn reference(&self) -> &PackageAbilityReference {
        &self.reference
    }

    fn validate(&self) -> Result<(), ReferenceInspectionError> {
        if self.schema != REFERENCE_INSPECTION_INPUT_SCHEMA {
            return Err(ReferenceInspectionError::UnsupportedSchema);
        }
        if !self.required_features.is_empty() {
            return Err(ReferenceInspectionError::UnsupportedFeatures);
        }

        let supported = ability_reference_supported_features()
            .map_err(|error| ReferenceInspectionError::InvalidReference(error.to_string()))?;
        let bytes = self
            .reference
            .canonical_json()
            .map_err(|error| ReferenceInspectionError::InvalidReference(error.to_string()))?;
        PackageAbilityReference::from_canonical_json(&bytes, &supported)
            .map_err(|error| ReferenceInspectionError::InvalidReference(error.to_string()))?;
        Ok(())
    }
}

impl CheckedReferenceInspection {
    /// Returns the exact canonical input digest.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    /// Reports whether checking matched an independently supplied commitment.
    #[must_use]
    pub const fn is_externally_anchored(&self) -> bool {
        self.externally_anchored
    }

    /// Returns the checked public package reference.
    #[must_use]
    pub const fn reference(&self) -> &PackageAbilityReference {
        self.input.reference()
    }
}

impl ReferenceInspectionView {
    /// Projects a checked public package reference into the shared graph model.
    ///
    /// # Errors
    ///
    /// Returns an error if exact interface identities conflict or the result
    /// exceeds a version-1 item or encoded-byte bound.
    pub fn from_checked(
        checked: &CheckedReferenceInspection,
    ) -> Result<Self, ReferenceInspectionError> {
        let reference = checked.reference();
        let package = NodeKey::Package(reference.manifest_sha256);
        let mut nodes = BTreeMap::from([(
            package.clone(),
            InspectionNode::Package {
                digest: reference.manifest_sha256,
                name: reference.package.clone(),
                version: reference.version.clone(),
                activation_mode: reference.activation_mode,
            },
        )]);
        let mut edges = BTreeSet::new();

        for export in &reference.exports {
            let key = export
                .interface
                .interface_key()
                .map_err(|error| ReferenceInspectionError::InvalidReference(error.to_string()))?;
            let node_key = NodeKey::Interface(key.clone());
            let node = InspectionNode::Interface {
                key,
                descriptor: export.interface.interface.clone(),
            };
            if nodes
                .insert(node_key.clone(), node.clone())
                .is_some_and(|existing| existing != node)
            {
                return Err(ReferenceInspectionError::InconsistentInterface);
            }
            edges.insert(InspectionEdge {
                from: package.clone(),
                to: node_key,
                relation: InspectionRelation::ExportsInterface,
            });
        }

        for requirement in &reference.requirements {
            for key in &requirement.accepted_interfaces {
                let node_key = NodeKey::Interface(key.clone());
                nodes
                    .entry(node_key.clone())
                    .or_insert_with(|| InspectionNode::InterfaceReference { key: key.clone() });
                edges.insert(InspectionEdge {
                    from: package.clone(),
                    to: node_key,
                    relation: InspectionRelation::RequiresInterface,
                });
            }
        }

        let view = Self {
            schema: REFERENCE_INSPECTION_VIEW_SCHEMA.to_string(),
            required_features: Vec::new(),
            anchor: reference_anchor(checked),
            disclosure: ReferenceInspectionDisclosure::PublicPackageContract,
            diagnostics: reference_diagnostics(),
            nodes: nodes.into_values().collect(),
            edges: edges.into_iter().collect(),
        };
        view.check_bounds()?;
        let _ = view.canonical_bytes()?;
        Ok(view)
    }

    /// Evaluates a bounded deterministic neighborhood query.
    ///
    /// # Errors
    ///
    /// Returns an error if the query is invalid or names an absent root.
    pub fn query(
        &self,
        query: &GraphQuery,
    ) -> Result<ReferenceGraphSlice, ReferenceInspectionError> {
        let selection = select_graph(&self.nodes, &self.edges, query)?;
        let slice = ReferenceGraphSlice {
            schema: REFERENCE_GRAPH_SLICE_SCHEMA.to_string(),
            required_features: Vec::new(),
            anchor: self.anchor.clone(),
            disclosure: self.disclosure,
            diagnostics: self.diagnostics.clone(),
            roots: query.roots().to_vec(),
            direction: query.direction(),
            after: query.after().cloned(),
            max_depth: query.max_depth(),
            max_nodes: query.max_nodes(),
            truncated: selection.truncated,
            nodes: selection.nodes,
            edges: selection.edges,
        };
        let _ = slice.canonical_bytes()?;
        Ok(slice)
    }

    /// Encodes the complete public-reference view as bounded canonical JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if the graph exceeds a bound or cannot be encoded.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ReferenceInspectionError> {
        self.check_bounds()?;
        bounded_canonical_bytes(self, REFERENCE_INSPECTION_VIEW_MAX_BYTES)
    }

    /// Returns the source and integrity status inherited from checked input.
    #[must_use]
    pub const fn anchor(&self) -> &ReferenceInspectionAnchor {
        &self.anchor
    }

    /// Returns the fixed public-only disclosure classification.
    #[must_use]
    pub const fn disclosure(&self) -> ReferenceInspectionDisclosure {
        self.disclosure
    }

    /// Returns shared limitation diagnostics in stable code order.
    #[must_use]
    pub fn diagnostics(&self) -> &[ReferenceInspectionDiagnostic] {
        &self.diagnostics
    }

    /// Returns nodes in stable typed-identity order.
    #[must_use]
    pub fn nodes(&self) -> &[InspectionNode] {
        &self.nodes
    }

    /// Returns edges in stable endpoint and relation order.
    #[must_use]
    pub fn edges(&self) -> &[InspectionEdge] {
        &self.edges
    }

    fn check_bounds(&self) -> Result<(), ReferenceInspectionError> {
        let limit = ABILITY_LIMITS_V1.max_graph_nodes as usize;
        if self.nodes.len() > limit || self.edges.len() > limit {
            return Err(ReferenceInspectionError::ItemLimit);
        }
        Ok(())
    }
}

impl ReferenceGraphSlice {
    /// Encodes this query result as bounded canonical JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if canonical encoding exceeds the version-1 bound.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ReferenceInspectionError> {
        bounded_canonical_bytes(self, REFERENCE_INSPECTION_VIEW_MAX_BYTES)
    }

    /// Returns the source and integrity status inherited from checked input.
    #[must_use]
    pub const fn anchor(&self) -> &ReferenceInspectionAnchor {
        &self.anchor
    }

    /// Returns the fixed public-only disclosure classification.
    #[must_use]
    pub const fn disclosure(&self) -> ReferenceInspectionDisclosure {
        self.disclosure
    }

    /// Returns shared limitation diagnostics in stable code order.
    #[must_use]
    pub fn diagnostics(&self) -> &[ReferenceInspectionDiagnostic] {
        &self.diagnostics
    }

    /// Reports whether a reachable node was omitted by a query bound.
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// Returns retained nodes in stable typed-identity order.
    #[must_use]
    pub fn nodes(&self) -> &[InspectionNode] {
        &self.nodes
    }

    /// Returns the induced edge set over retained nodes.
    #[must_use]
    pub fn edges(&self) -> &[InspectionEdge] {
        &self.edges
    }
}

fn reference_anchor(checked: &CheckedReferenceInspection) -> ReferenceInspectionAnchor {
    if checked.is_externally_anchored() {
        ReferenceInspectionAnchor::ExternallyAnchoredReference {
            digest: checked.digest(),
        }
    } else {
        ReferenceInspectionAnchor::UnanchoredReference {
            digest: checked.digest(),
        }
    }
}

fn reference_diagnostics() -> Vec<ReferenceInspectionDiagnostic> {
    [
        (
            ReferenceInspectionDiagnosticCode::DeploymentAuthorizationNotEvaluated,
            "The public package reference does not establish deployment authorization.",
        ),
        (
            ReferenceInspectionDiagnosticCode::ConditionalRequirementsNotEvaluated,
            "Conditional requirements have not been evaluated for a deployment environment.",
        ),
        (
            ReferenceInspectionDiagnosticCode::RuntimeAvailabilityNotObserved,
            "No live provider, resource, or runtime availability was observed.",
        ),
    ]
    .into_iter()
    .map(|(code, message)| ReferenceInspectionDiagnostic {
        code,
        message: message.to_string(),
    })
    .collect()
}

fn bounded_canonical_bytes(
    value: &impl Serialize,
    limit: usize,
) -> Result<Vec<u8>, ReferenceInspectionError> {
    let mut writer = ReferenceBoundedWriter::new(limit);
    serde_json::to_writer(&mut writer, value).map_err(|error| {
        if writer.exceeded {
            ReferenceInspectionError::EncodedSizeLimit
        } else {
            ReferenceInspectionError::Encode(error.to_string())
        }
    })?;
    aos_contract::canonical::to_vec(value)
        .map_err(|error| ReferenceInspectionError::Encode(error.to_string()))
}

struct ReferenceBoundedWriter {
    remaining: usize,
    exceeded: bool,
}

impl ReferenceBoundedWriter {
    const fn new(limit: usize) -> Self {
        Self {
            remaining: limit,
            exceeded: false,
        }
    }
}

impl Write for ReferenceBoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.remaining {
            self.exceeded = true;
            return Err(io::Error::other(
                "serialized reference inspection exceeds its byte limit",
            ));
        }
        self.remaining -= bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn input_limits() -> JsonLimits {
    JsonLimits {
        max_bytes: REFERENCE_INSPECTION_INPUT_MAX_BYTES,
        max_depth: ABILITY_LIMITS_V1.max_structural_depth as usize,
        max_items: ABILITY_LIMITS_V1.max_collection_items as usize,
        max_string_bytes: ABILITY_LIMITS_V1.max_string_bytes as usize,
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use aos_ability_model::{
        AbilityActivationMode, InterfaceDescriptor, InterfaceDocument, InterfaceName,
        LifecycleSemantics, LocalKey, RequiredFeature, ValueSchema,
    };
    use aos_doc_model::AbilityExportReference;

    use super::*;

    #[test]
    fn public_reference_query_retains_shared_identity_relations_and_limits()
    -> Result<(), Box<dyn std::error::Error>> {
        let reference = reference();
        let input = ReferenceInspectionInput::new(reference.clone())?;
        let input_bytes = input.canonical_bytes()?;
        let digest = Sha256Digest::of_bytes(&input_bytes);
        let checked = ReferenceInspectionInput::decode(&input_bytes)?.check(Some(digest))?;
        let view = ReferenceInspectionView::from_checked(&checked)?;
        let root = NodeKey::Package(reference.manifest_sha256);
        let slice = view.query(&GraphQuery::new([root], 1, 2))?;

        assert!(matches!(
            slice.anchor(),
            ReferenceInspectionAnchor::ExternallyAnchoredReference { digest: actual }
                if *actual == digest
        ));
        assert_eq!(
            slice.disclosure(),
            ReferenceInspectionDisclosure::PublicPackageContract
        );
        assert!(!slice.is_truncated());
        assert_eq!(slice.nodes().len(), 2);
        assert_eq!(slice.edges().len(), 1);
        assert_eq!(slice.diagnostics().len(), 3);
        let encoded = slice.canonical_bytes()?;
        assert!(!String::from_utf8(encoded)?.contains("deployment-values"));
        Ok(())
    }

    #[test]
    fn checking_rejects_a_wrong_external_commitment() -> Result<(), Box<dyn std::error::Error>> {
        let input = ReferenceInspectionInput::new(reference())?;
        let wrong = Sha256Digest::of_bytes(b"wrong reference");

        assert!(matches!(
            input.check(Some(wrong)),
            Err(ReferenceInspectionError::DigestMismatch)
        ));
        Ok(())
    }

    #[test]
    fn canonical_reference_query_matches_the_cross_frontend_golden_slice()
    -> Result<(), Box<dyn std::error::Error>> {
        let input_bytes =
            include_bytes!("../../../tests/abilities/fixtures/reference-inspection-input.json");
        let query_bytes =
            include_bytes!("../../../tests/abilities/fixtures/reference-inspection-query.json");
        let expected =
            include_bytes!("../../../tests/abilities/fixtures/reference-inspection-slice.json");
        let input = ReferenceInspectionInput::decode(input_bytes)?;
        let digest = Sha256Digest::of_bytes(input_bytes);
        let checked = input.check(Some(digest))?;
        let view = ReferenceInspectionView::from_checked(&checked)?;
        let query = GraphQuery::decode(query_bytes)?;

        assert_eq!(view.query(&query)?.canonical_bytes()?, expected);
        Ok(())
    }

    fn reference() -> PackageAbilityReference {
        let interface = InterfaceDocument {
            schema: "aos.ability.interface/v1".to_string(),
            required_features: vec![RequiredFeature::new("abilities-v1").expect("feature")],
            interface: InterfaceDescriptor {
                name: InterfaceName::new("aos.test.service").expect("interface"),
                abi: NonZeroU32::new(1).expect("nonzero ABI"),
                request: ValueSchema::Boolean,
                configuration: None,
                outputs: BTreeMap::new(),
                methods: BTreeMap::new(),
                lifecycle: LifecycleSemantics {
                    stable_resource_identity: true,
                    releases_ephemeral_on_disable: true,
                    retains_persistent_by_default: false,
                    persistent_delete_method: None,
                },
                guarantees: Vec::new(),
            },
        };
        PackageAbilityReference {
            schema: aos_doc_model::ABILITY_REFERENCE_SCHEMA.to_string(),
            required_features: vec![RequiredFeature::new("abilities-v1").expect("feature")],
            package: LocalKey::new("demo").expect("package"),
            version: "1.0.0".to_string(),
            manifest_sha256: Sha256Digest::of_bytes(b"manifest"),
            package_digest: Sha256Digest::of_bytes(b"package"),
            activation_mode: AbilityActivationMode::ContractsOnly,
            exports: vec![AbilityExportReference {
                name: LocalKey::new("service").expect("export"),
                interface,
                aggregation: None,
                implementation: Sha256Digest::of_bytes(b"implementation"),
            }],
            requirements: Vec::new(),
            handlers: Vec::new(),
            ownership: Vec::new(),
        }
    }
}
