//! Canonical package documentation shared by APM, Hub, Web, and tooling.
//!
//! This crate owns the closed `aos.package-documentation/v1` data contract,
//! its canonical JSON encoding, semantic schema identity, deterministic search
//! projection, and safe plain-text, HTML, and roff renderers. It performs no
//! I/O and has no native-only dependencies, so the native Hub, Cloudflare
//! Worker, browser tooling, and local APM consume the same semantics.
//!
//! A canonical document is a single UTF-8 JSON file. Unknown fields are
//! rejected by Serde, floating-point literals and Nix store references are
//! forbidden, and [`PackageDocumentation::validate`] enforces the bounded
//! collection and cross-field invariants before any renderer sees content.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

mod nar;

pub use nar::decode_single_file_nar;

/// Canonical schema identifier carried inside every document.
pub const DOCUMENT_SCHEMA: &str = "aos.package-documentation/v1";

/// Media/format identifier advertised by signed registry metadata.
pub const DOCUMENT_FORMAT: &str = "aos.package-documentation/v1+json";

/// Closed JSON Schema served to editors and language tooling.
pub const DOCUMENT_JSON_SCHEMA: &str = include_str!("../schema-v1.json");

/// Maximum canonical document size admitted by version 1.
pub const MAX_DOCUMENT_BYTES: usize = 4 * 1024 * 1024;

const MAX_OPTIONS: usize = 16_384;
const MAX_SECTIONS: usize = 256;
const MAX_RUNTIME_ITEMS: usize = 8_192;
const MAX_TEXT_BYTES: usize = 256 * 1024;
const MAX_LITERAL_DEPTH: usize = 32;
const MAX_LITERAL_ITEMS: usize = 16_384;

/// Errors returned while decoding, validating, or rendering documentation.
#[derive(Debug, Error)]
pub enum DocumentationError {
    /// The input is not valid JSON for the closed schema.
    #[error("invalid package documentation JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// A model or cross-artifact invariant is violated.
    #[error("invalid package documentation: {0}")]
    Invalid(String),
}

/// Result type used by package-documentation operations.
pub type Result<T> = std::result::Result<T, DocumentationError>;

/// One canonical package documentation object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageDocumentation {
    /// Closed document schema identifier.
    pub schema: String,
    /// Package selection described by this object.
    pub package: DocumentedPackage,
    /// Content and cross-artifact identities without store paths.
    pub identity: DocumentationIdentity,
    /// Package-authored structured explanatory sections.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sections: Vec<Section>,
    /// Mechanically extracted option reference.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<OptionDocument>,
    /// Mechanically derived runtime surface.
    #[serde(default)]
    pub runtime: RuntimeSurface,
}

/// Package identity and short catalog metadata embedded in a document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentedPackage {
    /// Registry package name.
    pub name: String,
    /// Exact published package version.
    pub version: String,
    /// Exact platform selector, such as `x86_64-linux`.
    pub platform: String,
    /// One-line human summary.
    pub summary: String,
    /// Optional validated HTTPS project home page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub homepage: Option<String>,
    /// SPDX-style license expression or identifier.
    pub license: String,
}

/// Semantic and artifact digests repeated for self-description.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentationIdentity {
    /// Digest over configuration meaning, excluding explanatory prose.
    pub semantic_schema_sha256: String,
    /// Runtime output NAR hash.
    pub runtime_nar_hash: String,
    /// Optional config-module NAR hash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_module_nar_hash: Option<String>,
    /// Optional expose-artifact NAR hash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expose_artifact_nar_hash: Option<String>,
    /// Source derivation closure NAR hash.
    pub source_nar_hash: String,
}

/// One package-authored conceptual section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Section {
    /// Stable document-local identifier.
    pub id: String,
    /// Human section title.
    pub title: String,
    /// Structured prose blocks.
    pub blocks: Vec<ProseBlock>,
}

/// Closed structured-prose block understood by every renderer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ProseBlock {
    /// A paragraph of safe inline spans.
    Paragraph {
        /// Paragraph contents.
        spans: Vec<InlineSpan>,
    },
    /// Ordered or unordered list.
    List {
        /// Whether item numbering is significant.
        ordered: bool,
        /// List items, each represented as structured blocks.
        items: Vec<Vec<ProseBlock>>,
    },
    /// Copy-safe source or command example.
    Code {
        /// Declared language label.
        language: String,
        /// Literal code bytes represented as UTF-8 text.
        text: String,
    },
    /// Visually distinguished information, warning, or security note.
    Note {
        /// Note severity.
        severity: NoteSeverity,
        /// Structured note body.
        blocks: Vec<ProseBlock>,
    },
    /// Definition table with structured bodies.
    Definitions {
        /// Ordered term definitions.
        entries: Vec<DefinitionEntry>,
    },
}

/// One safe inline prose span.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum InlineSpan {
    /// Plain text.
    Text {
        /// Literal text.
        text: String,
    },
    /// Inline code.
    Code {
        /// Literal code text.
        text: String,
    },
    /// A typed link whose presentation is renderer-owned.
    Link {
        /// Visible label.
        label: String,
        /// Typed link destination.
        target: LinkTarget,
    },
}

/// Link destination admitted by structured prose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum LinkTarget {
    /// Another package in the selected registry.
    Package {
        /// Package name.
        package: String,
    },
    /// An exact structured option path.
    Option {
        /// Option path.
        path: Vec<PathSegment>,
    },
    /// A section in the current document.
    Section {
        /// Section identifier.
        id: String,
    },
    /// A repository-relative source locator.
    Source {
        /// Repository-relative path.
        path: String,
    },
    /// A validated HTTPS URL.
    Https {
        /// Absolute HTTPS URL.
        url: String,
    },
}

/// Note severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NoteSeverity {
    /// General useful information.
    Info,
    /// Operational caution.
    Warning,
    /// Security-sensitive guidance.
    Security,
}

/// One definition-table row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DefinitionEntry {
    /// Plain-text term.
    pub term: String,
    /// Structured definition body.
    pub body: Vec<ProseBlock>,
}

/// One exact or dynamic option-path segment.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum PathSegment {
    /// Exact option attribute segment.
    Literal {
        /// Attribute name.
        value: String,
    },
    /// Dynamic attrs-of or submodule name.
    Wildcard {
        /// Human placeholder without angle brackets.
        name: String,
    },
}

impl PathSegment {
    fn display(&self) -> String {
        match self {
            Self::Literal { value } => value.clone(),
            Self::Wildcard { name } => format!("<{name}>"),
        }
    }
}

/// Closed rich option type algebra.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum OptionType {
    /// Boolean value.
    Bool,
    /// Signed integer value.
    Integer {
        /// Inclusive lower bound.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        min: Option<i64>,
        /// Inclusive upper bound.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max: Option<i64>,
    },
    /// Unsigned integer value.
    Unsigned {
        /// Inclusive lower bound.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        min: Option<u64>,
        /// Inclusive upper bound.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max: Option<u64>,
    },
    /// String with optional constraints.
    String {
        /// Optional regular-expression description.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pattern: Option<String>,
        /// Optional maximum byte length.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_length: Option<u64>,
    },
    /// TCP/UDP port number.
    Port,
    /// Filesystem path.
    Path,
    /// Duration value.
    Duration,
    /// CIDR network prefix.
    Cidr,
    /// Opaque credential or secret reference.
    OpaqueReference,
    /// Enumerated string values.
    Enum {
        /// Admitted values and their optional descriptions.
        values: Vec<EnumValue>,
    },
    /// Ordered list.
    List {
        /// Element type.
        element: Box<OptionType>,
        /// Whether duplicate values are forbidden.
        #[serde(default)]
        unique: bool,
    },
    /// Unordered semantic set.
    Set {
        /// Element type.
        element: Box<OptionType>,
    },
    /// Attribute map with dynamic keys.
    AttrsOf {
        /// Value type.
        value: Box<OptionType>,
        /// Dynamic segment placeholder.
        placeholder: String,
    },
    /// Fixed-field record.
    Submodule {
        /// Sorted fixed fields.
        fields: BTreeMap<String, OptionType>,
        /// Whether unknown additional attributes are admitted.
        #[serde(default)]
        open: bool,
    },
    /// Nullable value.
    Nullable {
        /// Non-null value type.
        value: Box<OptionType>,
    },
    /// Bounded union.
    OneOf {
        /// Alternative types.
        alternatives: Vec<OptionType>,
    },
    /// Stable fallback for an AOS type that has not yet gained a rich variant.
    Opaque {
        /// Stable type signature.
        signature: String,
    },
}

/// One enum value and its structured description.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnumValue {
    /// Literal value.
    pub value: String,
    /// Structured value description.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub description: Vec<ProseBlock>,
}

/// A safe option default or example.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum DocumentedValue {
    /// Bounded JSON-compatible literal.
    Literal {
        /// Literal value; floats are rejected during validation.
        value: Value,
    },
    /// Human text for a computed value that must not be forced.
    Text {
        /// Stable explanatory text.
        text: String,
    },
}

/// Public visibility of an option or runtime fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Visibility {
    /// Public user-facing interface.
    Public,
    /// Internal interface available to authenticated tooling.
    Internal,
    /// Hidden implementation plumbing.
    Hidden,
}

/// Authenticated owner of an option path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OptionOwner {
    /// Package declaring or owning the option.
    pub package: String,
    /// Owned root.
    pub root: String,
    /// Root interface ABI when the root is shared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface_abi: Option<u32>,
}

/// Effect expected when an option changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationEffect {
    /// Activation action.
    pub kind: ActivationKind,
    /// Exact affected systemd units.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub units: Vec<String>,
}

/// Closed activation action vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ActivationKind {
    /// No live action.
    None,
    /// Re-evaluate configuration only.
    Reevaluate,
    /// Reload live service state.
    Reload,
    /// Restart affected services.
    Restart,
    /// Recreate runtime resources.
    Recreate,
    /// Reboot the system.
    Reboot,
    /// Package-specific lifecycle operation.
    PackageOperation,
}

/// Repository-relative declaration locator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceLocator {
    /// Repository-relative source path.
    pub path: String,
    /// Optional stable attribute locator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    /// Optional one-based source line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
}

/// One mechanically extracted option document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OptionDocument {
    /// Structured path segments.
    pub path: Vec<PathSegment>,
    /// Checked human presentation of [`Self::path`].
    pub display_path: String,
    /// Rich type model.
    #[serde(rename = "type")]
    pub option_type: OptionType,
    /// Stable module-engine type signature.
    pub type_signature: String,
    /// Structured public description.
    pub description: Vec<ProseBlock>,
    /// Safe default or computed-value text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<DocumentedValue>,
    /// Safe example.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub example: Option<DocumentedValue>,
    /// User visibility.
    pub visibility: Visibility,
    /// Whether the option is read-only.
    #[serde(default)]
    pub read_only: bool,
    /// Optional deprecation notice.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deprecated: Option<String>,
    /// Structured replacement option.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replacement: Option<Vec<PathSegment>>,
    /// Authenticated option owner.
    pub owner: OptionOwner,
    /// Whether non-owner packages may contribute below this option.
    #[serde(default)]
    pub contributable: bool,
    /// Expected live activation effect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activation: Option<ActivationEffect>,
    /// Declaration source locator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<SourceLocator>,
}

/// Runtime interface derived from expose/config package metadata.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSurface {
    /// Authenticated unit inventory.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub units: Vec<RuntimeUnit>,
    /// Declared network listeners.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub listeners: Vec<RuntimeListener>,
    /// State/cache/log/runtime/config paths.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub managed_paths: Vec<ManagedPath>,
    /// Typed rendered configuration artifacts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub config_artifacts: Vec<RuntimeConfigArtifact>,
    /// Credential contracts without secret values.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credentials: Vec<CredentialContract>,
    /// Provided/used capability tokens.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<RuntimeCapability>,
    /// Workload confinement summary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confinement: Option<ConfinementSummary>,
}

/// One systemd runtime unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeUnit {
    /// Exact unit name.
    pub name: String,
    /// Unit kind.
    pub kind: String,
    /// Human summary.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub summary: String,
    /// Units required before this unit.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires: Vec<String>,
}

/// One declared network listener.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeListener {
    /// Owning unit.
    pub unit: String,
    /// Transport protocol.
    pub protocol: String,
    /// Optional port when statically known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Declared network mode.
    pub network_mode: String,
}

/// One managed runtime path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedPath {
    /// Absolute path without store identity.
    pub path: String,
    /// State, cache, log, runtime, or configuration.
    pub purpose: String,
    /// Whether the workload may write the path.
    pub writable: bool,
}

/// One rendered configuration artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfigArtifact {
    /// Signed artifact handle.
    pub name: String,
    /// Destination path.
    pub destination: String,
    /// Stable format name.
    pub format: String,
    /// Reload or restart action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activation: Option<ActivationEffect>,
}

/// One credential declaration without secret material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialContract {
    /// Signed credential handle.
    pub name: String,
    /// Human purpose.
    pub purpose: String,
    /// Volatile workload destination.
    pub destination: String,
    /// Accepted opaque-reference source kinds.
    pub accepted_kinds: Vec<String>,
    /// Whether configuration requires the credential.
    pub required: bool,
    /// File mode delivered to the workload.
    pub mode: u32,
    /// Live action after rotation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activation: Option<ActivationEffect>,
}

/// One provided or consumed typed capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeCapability {
    /// Capability token.
    pub name: String,
    /// `provides` or `uses`.
    pub direction: String,
}

/// High-level confinement information suitable for reference docs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfinementSummary {
    /// Confinement class.
    pub class: String,
    /// Network confinement mode.
    pub network: String,
    /// Whether the workload has a private root.
    pub private_root: bool,
}

/// One deterministic search row derived from a canonical document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchDocument {
    /// Result kind (`package`, `option`, `service`, `credential`, or
    /// `capability`).
    pub kind: String,
    /// Stable document-local key.
    pub key: String,
    /// Human title.
    pub title: String,
    /// Bounded plain-text summary.
    pub summary: String,
    /// Normalized deterministic terms with integer weights.
    pub terms: BTreeMap<String, u16>,
}

impl PackageDocumentation {
    /// Decodes canonical JSON and rejects non-canonical or invalid input.
    ///
    /// # Errors
    ///
    /// Returns an error when JSON decoding fails, unknown fields are present,
    /// the model violates a bound/invariant, or the bytes are not the one
    /// canonical encoding of the value.
    pub fn from_canonical_json(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_DOCUMENT_BYTES {
            return Err(invalid("document exceeds the 4 MiB limit"));
        }
        let document: Self = serde_json::from_slice(bytes)?;
        document.validate()?;
        let canonical = document.canonical_json()?;
        if canonical != bytes {
            return Err(invalid("input is not canonical JSON"));
        }
        Ok(document)
    }

    /// Validates all closed-schema limits and semantic invariants.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid identities, paths, structured prose,
    /// unsafe literals, duplicate keys, store references, or exceeded limits.
    pub fn validate(&self) -> Result<()> {
        if self.schema != DOCUMENT_SCHEMA {
            return Err(invalid(format!("unsupported schema '{}'", self.schema)));
        }
        validate_token("package name", &self.package.name)?;
        validate_nonempty("package version", &self.package.version)?;
        validate_token("platform", &self.package.platform)?;
        validate_text("package summary", &self.package.summary)?;
        validate_nonempty("package license", &self.package.license)?;
        if let Some(homepage) = &self.package.homepage {
            validate_https(homepage)?;
        }
        validate_digest(
            "semantic schema digest",
            &self.identity.semantic_schema_sha256,
        )?;
        validate_digest("runtime NAR hash", &self.identity.runtime_nar_hash)?;
        validate_optional_digest(
            "config-module NAR hash",
            self.identity.config_module_nar_hash.as_deref(),
        )?;
        validate_optional_digest(
            "expose-artifact NAR hash",
            self.identity.expose_artifact_nar_hash.as_deref(),
        )?;
        validate_digest("source NAR hash", &self.identity.source_nar_hash)?;

        if self.sections.len() > MAX_SECTIONS {
            return Err(invalid("too many package sections"));
        }
        let mut section_ids = BTreeSet::new();
        for section in &self.sections {
            validate_token("section id", &section.id)?;
            validate_text("section title", &section.title)?;
            if !section_ids.insert(section.id.as_str()) {
                return Err(invalid(format!("duplicate section '{}'", section.id)));
            }
            validate_blocks(&section.blocks, 0)?;
        }

        if self.options.len() > MAX_OPTIONS {
            return Err(invalid("too many options"));
        }
        let mut option_paths = BTreeSet::new();
        for option in &self.options {
            validate_option(option)?;
            if !option_paths.insert(option.display_path.as_str()) {
                return Err(invalid(format!(
                    "duplicate option '{}'",
                    option.display_path
                )));
            }
        }
        validate_runtime(&self.runtime)?;

        let canonical = serde_json::to_vec(self)?;
        if canonical.len() > MAX_DOCUMENT_BYTES {
            return Err(invalid("canonical document exceeds the 4 MiB limit"));
        }
        if find_store_reference(&canonical) {
            return Err(invalid("document contains a forbidden Nix store path"));
        }
        Ok(())
    }

    /// Encodes the document into the one canonical UTF-8 JSON representation.
    ///
    /// # Errors
    ///
    /// Returns an error when validation or JSON serialization fails.
    pub fn canonical_json(&self) -> Result<Vec<u8>> {
        self.validate()?;
        Ok(serde_json::to_vec(self)?)
    }

    /// Returns the SHA-256 identity of the canonical document bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when the document is invalid or cannot be encoded.
    pub fn document_sha256(&self) -> Result<String> {
        Ok(sha256(&self.canonical_json()?))
    }

    /// Computes the digest over configuration meaning, excluding prose.
    ///
    /// # Errors
    ///
    /// Returns an error when the document is invalid or the semantic
    /// projection cannot be encoded.
    pub fn computed_semantic_schema_sha256(&self) -> Result<String> {
        self.validate_without_semantic_identity()?;
        let projection = SemanticProjection::from(self);
        Ok(sha256(&serde_json::to_vec(&projection)?))
    }

    /// Checks that the embedded semantic digest matches the derived schema.
    ///
    /// # Errors
    ///
    /// Returns an error when the document is invalid or the digest differs.
    pub fn verify_semantic_schema_sha256(&self) -> Result<()> {
        let computed = self.computed_semantic_schema_sha256()?;
        if computed != self.identity.semantic_schema_sha256 {
            return Err(invalid(format!(
                "semantic schema digest mismatch: recorded {}, computed {computed}",
                self.identity.semantic_schema_sha256
            )));
        }
        Ok(())
    }

    /// Derives deterministic bounded search rows.
    pub fn search_documents(&self) -> Vec<SearchDocument> {
        let mut rows = Vec::with_capacity(1 + self.options.len() + self.runtime.units.len());
        rows.push(search_row(
            "package",
            &self.package.name,
            &self.package.name,
            &self.package.summary,
            [(&self.package.name, 100), (&self.package.summary, 30)],
        ));
        for option in &self.options {
            let summary = prose_plain_text(&option.description);
            rows.push(search_row(
                "option",
                &option.display_path,
                &option.display_path,
                &summary,
                [
                    (option.display_path.as_str(), 100),
                    (option.type_signature.as_str(), 40),
                    (summary.as_str(), 20),
                ],
            ));
        }
        for unit in &self.runtime.units {
            rows.push(search_row(
                "service",
                &unit.name,
                &unit.name,
                &unit.summary,
                [(&unit.name, 100), (&unit.summary, 20)],
            ));
        }
        for credential in &self.runtime.credentials {
            rows.push(search_row(
                "credential",
                &credential.name,
                &credential.name,
                &credential.purpose,
                [(&credential.name, 100), (&credential.purpose, 30)],
            ));
        }
        for capability in &self.runtime.capabilities {
            rows.push(search_row(
                "capability",
                &capability.name,
                &capability.name,
                &capability.direction,
                [(&capability.name, 100), (&capability.direction, 20)],
            ));
        }
        rows
    }

    /// Renders complete, escape-free plain text suitable for terminals.
    pub fn render_plain(&self) -> String {
        let mut output = format!(
            "{} {} ({})\n{}\n",
            self.package.name, self.package.version, self.package.platform, self.package.summary
        );
        for section in &self.sections {
            output.push_str(&format!(
                "\n{}\n{}\n",
                section.title,
                "-".repeat(section.title.len())
            ));
            render_blocks_plain(&section.blocks, &mut output, 0);
        }
        if !self.options.is_empty() {
            output.push_str("\nOPTIONS\n-------\n");
            for option in &self.options {
                output.push_str(&format!(
                    "\n{} ({})\n{}\n",
                    option.display_path,
                    option.type_signature,
                    prose_plain_text(&option.description)
                ));
            }
        }
        output
    }

    /// Renders safe content-bearing HTML without package-controlled markup.
    pub fn render_html(&self) -> String {
        let mut output = String::from(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>",
        );
        escape_html_into(&self.package.name, &mut output);
        output.push_str(" documentation</title></head><body>");
        self.render_html_fragment_into(&mut output);
        output.push_str("</body></html>");
        output
    }

    /// Renders safe embeddable HTML for Web UIs.
    ///
    /// Package-authored content is represented by the closed structured-prose
    /// model, and every literal is escaped before it reaches the returned
    /// fragment. The result therefore contains no document wrapper, script,
    /// style, or untrusted markup.
    #[must_use]
    pub fn render_html_fragment(&self) -> String {
        let mut output = String::new();
        self.render_html_fragment_into(&mut output);
        output
    }

    fn render_html_fragment_into(&self, output: &mut String) {
        output.push_str("<main class=\"package-documentation\"><header><h1>");
        escape_html_into(&self.package.name, output);
        output.push_str("</h1><p>");
        escape_html_into(&self.package.summary, output);
        output.push_str("</p><p><code>");
        escape_html_into(&self.package.version, output);
        output.push_str(" · ");
        escape_html_into(&self.package.platform, output);
        output.push_str("</code></p></header>");
        for section in &self.sections {
            output.push_str("<section id=\"");
            escape_html_into(&section.id, output);
            output.push_str("\"><h2>");
            escape_html_into(&section.title, output);
            output.push_str("</h2>");
            render_blocks_html(&section.blocks, output);
            output.push_str("</section>");
        }
        if !self.options.is_empty() {
            output.push_str("<section id=\"options\"><h2>Options</h2><dl>");
            for option in &self.options {
                output.push_str("<dt><code>");
                escape_html_into(&option.display_path, output);
                output.push_str("</code></dt><dd><p><strong>");
                escape_html_into(&option.type_signature, output);
                output.push_str("</strong></p>");
                render_blocks_html(&option.description, output);
                output.push_str("</dd>");
            }
            output.push_str("</dl></section>");
        }
        output.push_str("</main>");
    }

    /// Renders safe roff source for an `apm-<package>(5)` manual page.
    pub fn render_roff(&self) -> String {
        let mut output = String::from(".TH \"");
        escape_roff_into(&self.package.name.to_uppercase(), &mut output);
        output.push_str("\" \"5\"\n.SH NAME\n");
        escape_roff_into(&self.package.name, &mut output);
        output.push_str(" \\- ");
        escape_roff_into(&self.package.summary, &mut output);
        output.push_str("\n.SH SYNOPSIS\nVersion ");
        escape_roff_into(&self.package.version, &mut output);
        output.push_str(" for ");
        escape_roff_into(&self.package.platform, &mut output);
        output.push('\n');
        for section in &self.sections {
            output.push_str(".SH \"");
            escape_roff_into(&section.title.to_uppercase(), &mut output);
            output.push_str("\"\n");
            render_blocks_roff(&section.blocks, &mut output);
        }
        if !self.options.is_empty() {
            output.push_str(".SH OPTIONS\n");
            for option in &self.options {
                output.push_str(".TP\n.B \"");
                escape_roff_into(&option.display_path, &mut output);
                output.push_str("\"\n");
                escape_roff_into(&prose_plain_text(&option.description), &mut output);
                output.push_str("\nType: ");
                escape_roff_into(&option.type_signature, &mut output);
                output.push('\n');
            }
        }
        output
    }

    fn validate_without_semantic_identity(&self) -> Result<()> {
        let mut copy = self.clone();
        copy.identity.semantic_schema_sha256 = format!("sha256:{}", "0".repeat(64));
        copy.validate()
    }
}

#[derive(Serialize)]
struct SemanticProjection<'a> {
    package: &'a str,
    version: &'a str,
    platform: &'a str,
    options: Vec<SemanticOption<'a>>,
    runtime: &'a RuntimeSurface,
}

#[derive(Serialize)]
struct SemanticOption<'a> {
    path: &'a [PathSegment],
    option_type: &'a OptionType,
    type_signature: &'a str,
    visibility: Visibility,
    read_only: bool,
    deprecated: &'a Option<String>,
    replacement: &'a Option<Vec<PathSegment>>,
    owner: &'a OptionOwner,
    contributable: bool,
    activation: &'a Option<ActivationEffect>,
}

impl<'a> From<&'a PackageDocumentation> for SemanticProjection<'a> {
    fn from(document: &'a PackageDocumentation) -> Self {
        Self {
            package: &document.package.name,
            version: &document.package.version,
            platform: &document.package.platform,
            options: document
                .options
                .iter()
                .map(|option| SemanticOption {
                    path: &option.path,
                    option_type: &option.option_type,
                    type_signature: &option.type_signature,
                    visibility: option.visibility,
                    read_only: option.read_only,
                    deprecated: &option.deprecated,
                    replacement: &option.replacement,
                    owner: &option.owner,
                    contributable: option.contributable,
                    activation: &option.activation,
                })
                .collect(),
            runtime: &document.runtime,
        }
    }
}

fn validate_option(option: &OptionDocument) -> Result<()> {
    if option.path.is_empty() || option.path.len() > 64 {
        return Err(invalid("option path must contain 1..=64 segments"));
    }
    for segment in &option.path {
        match segment {
            PathSegment::Literal { value } => validate_token("option path segment", value)?,
            PathSegment::Wildcard { name } => validate_token("option wildcard", name)?,
        }
    }
    let expected = option
        .path
        .iter()
        .map(PathSegment::display)
        .collect::<Vec<_>>()
        .join(".");
    if option.display_path != expected {
        return Err(invalid(format!(
            "option display path '{}' does not match structured path '{expected}'",
            option.display_path
        )));
    }
    validate_nonempty("option type signature", &option.type_signature)?;
    validate_option_type(&option.option_type, 0)?;
    validate_blocks(&option.description, 0)?;
    if option.visibility == Visibility::Public && prose_plain_text(&option.description).is_empty() {
        return Err(invalid(format!(
            "public option '{}' has no description",
            option.display_path
        )));
    }
    if let Some(value) = &option.default {
        validate_documented_value(value)?;
    }
    if let Some(value) = &option.example {
        validate_documented_value(value)?;
    }
    validate_token("option owner package", &option.owner.package)?;
    validate_token("option owner root", &option.owner.root)?;
    if let Some(source) = &option.source {
        validate_relative_source_path(&source.path)?;
    }
    if let Some(activation) = &option.activation {
        validate_sorted_unique("activation units", &activation.units)?;
    }
    Ok(())
}

fn validate_option_type(option_type: &OptionType, depth: usize) -> Result<()> {
    if depth > 32 {
        return Err(invalid("option type nesting exceeds 32"));
    }
    match option_type {
        OptionType::Integer { min, max } if min.zip(*max).is_some_and(|(a, b)| a > b) => {
            Err(invalid("integer type range is inverted"))
        }
        OptionType::Unsigned { min, max } if min.zip(*max).is_some_and(|(a, b)| a > b) => {
            Err(invalid("unsigned type range is inverted"))
        }
        OptionType::String {
            pattern,
            max_length,
        } => {
            if let Some(pattern) = pattern {
                validate_text("string constraint pattern", pattern)?;
            }
            if max_length.is_some_and(|length| length > MAX_TEXT_BYTES as u64) {
                return Err(invalid("string maximum exceeds document text limit"));
            }
            Ok(())
        }
        OptionType::Enum { values } => {
            if values.is_empty() || values.len() > 4096 {
                return Err(invalid("enum must contain 1..=4096 values"));
            }
            let mut seen = BTreeSet::new();
            for value in values {
                validate_text("enum value", &value.value)?;
                validate_blocks(&value.description, 0)?;
                if !seen.insert(value.value.as_str()) {
                    return Err(invalid(format!("duplicate enum value '{}'", value.value)));
                }
            }
            Ok(())
        }
        OptionType::List { element, .. }
        | OptionType::Set { element }
        | OptionType::AttrsOf { value: element, .. }
        | OptionType::Nullable { value: element } => validate_option_type(element, depth + 1),
        OptionType::Submodule { fields, .. } => {
            if fields.len() > 4096 {
                return Err(invalid("submodule has too many fields"));
            }
            for (name, field_type) in fields {
                validate_token("submodule field", name)?;
                validate_option_type(field_type, depth + 1)?;
            }
            Ok(())
        }
        OptionType::OneOf { alternatives } => {
            if alternatives.is_empty() || alternatives.len() > 32 {
                return Err(invalid("one-of must contain 1..=32 alternatives"));
            }
            for alternative in alternatives {
                validate_option_type(alternative, depth + 1)?;
            }
            Ok(())
        }
        OptionType::Opaque { signature } => validate_nonempty("opaque type signature", signature),
        _ => Ok(()),
    }
}

fn validate_documented_value(value: &DocumentedValue) -> Result<()> {
    match value {
        DocumentedValue::Literal { value } => {
            let mut items = 0;
            validate_literal(value, 0, &mut items)
        }
        DocumentedValue::Text { text } => validate_text("documented value text", text),
    }
}

fn validate_literal(value: &Value, depth: usize, items: &mut usize) -> Result<()> {
    if depth > MAX_LITERAL_DEPTH {
        return Err(invalid("literal nesting exceeds 32"));
    }
    *items += 1;
    if *items > MAX_LITERAL_ITEMS {
        return Err(invalid("literal contains too many values"));
    }
    match value {
        Value::Number(number) if !number.is_i64() && !number.is_u64() => {
            Err(invalid("floating-point literals are forbidden"))
        }
        Value::String(text) => validate_text("literal string", text),
        Value::Array(values) => {
            for value in values {
                validate_literal(value, depth + 1, items)?;
            }
            Ok(())
        }
        Value::Object(values) => {
            for (key, value) in values {
                validate_text("literal key", key)?;
                validate_literal(value, depth + 1, items)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn validate_blocks(blocks: &[ProseBlock], depth: usize) -> Result<()> {
    if depth > 24 {
        return Err(invalid("structured prose nesting exceeds 24"));
    }
    if blocks.len() > 4096 {
        return Err(invalid("structured prose contains too many blocks"));
    }
    for block in blocks {
        match block {
            ProseBlock::Paragraph { spans } => {
                if spans.len() > 4096 {
                    return Err(invalid("paragraph contains too many spans"));
                }
                for span in spans {
                    validate_inline(span)?;
                }
            }
            ProseBlock::List { items, .. } => {
                if items.len() > 4096 {
                    return Err(invalid("list contains too many items"));
                }
                for item in items {
                    validate_blocks(item, depth + 1)?;
                }
            }
            ProseBlock::Code { language, text } => {
                validate_token("code language", language)?;
                validate_text("code block", text)?;
            }
            ProseBlock::Note { blocks, .. } => validate_blocks(blocks, depth + 1)?,
            ProseBlock::Definitions { entries } => {
                if entries.len() > 4096 {
                    return Err(invalid("definition table contains too many entries"));
                }
                for entry in entries {
                    validate_text("definition term", &entry.term)?;
                    validate_blocks(&entry.body, depth + 1)?;
                }
            }
        }
    }
    Ok(())
}

fn validate_inline(span: &InlineSpan) -> Result<()> {
    match span {
        InlineSpan::Text { text } | InlineSpan::Code { text } => validate_text("inline text", text),
        InlineSpan::Link { label, target } => {
            validate_text("link label", label)?;
            match target {
                LinkTarget::Package { package } => validate_token("linked package", package),
                LinkTarget::Option { path } => {
                    if path.is_empty() {
                        return Err(invalid("linked option path is empty"));
                    }
                    Ok(())
                }
                LinkTarget::Section { id } => validate_token("linked section", id),
                LinkTarget::Source { path } => validate_relative_source_path(path),
                LinkTarget::Https { url } => validate_https(url),
            }
        }
    }
}

fn validate_runtime(runtime: &RuntimeSurface) -> Result<()> {
    let total = runtime.units.len()
        + runtime.listeners.len()
        + runtime.managed_paths.len()
        + runtime.config_artifacts.len()
        + runtime.credentials.len()
        + runtime.capabilities.len();
    if total > MAX_RUNTIME_ITEMS {
        return Err(invalid("runtime surface contains too many items"));
    }
    validate_unique_by(
        "runtime unit",
        runtime.units.iter().map(|unit| unit.name.as_str()),
    )?;
    validate_unique_by(
        "config artifact",
        runtime
            .config_artifacts
            .iter()
            .map(|artifact| artifact.name.as_str()),
    )?;
    validate_unique_by(
        "credential",
        runtime
            .credentials
            .iter()
            .map(|credential| credential.name.as_str()),
    )?;
    Ok(())
}

fn validate_unique_by<'a>(label: &str, values: impl Iterator<Item = &'a str>) -> Result<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        validate_text(label, value)?;
        if !seen.insert(value) {
            return Err(invalid(format!("duplicate {label} '{value}'")));
        }
    }
    Ok(())
}

fn validate_sorted_unique(label: &str, values: &[String]) -> Result<()> {
    for value in values {
        validate_text(label, value)?;
    }
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(invalid(format!("{label} must be sorted and unique")));
    }
    Ok(())
}

fn validate_token(label: &str, value: &str) -> Result<()> {
    validate_nonempty(label, value)?;
    if value.len() > 512
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"+._=@-".contains(&byte))
        || !value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
    {
        return Err(invalid(format!("{label} '{value}' is not a safe token")));
    }
    Ok(())
}

fn validate_nonempty(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > MAX_TEXT_BYTES {
        return Err(invalid(format!("{label} is empty or too large")));
    }
    Ok(())
}

fn validate_text(label: &str, value: &str) -> Result<()> {
    validate_nonempty(label, value)?;
    if value.contains('\0') || value.contains("/nix/store/") {
        return Err(invalid(format!("{label} contains forbidden content")));
    }
    Ok(())
}

fn validate_digest(label: &str, value: &str) -> Result<()> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(invalid(format!("{label} must use sha256:<hex>")));
    };
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid(format!("{label} is not a 32-byte hex digest")));
    }
    Ok(())
}

fn validate_optional_digest(label: &str, value: Option<&str>) -> Result<()> {
    if let Some(value) = value {
        validate_digest(label, value)?;
    }
    Ok(())
}

fn validate_https(value: &str) -> Result<()> {
    validate_text("HTTPS URL", value)?;
    if !value.starts_with("https://") || value.contains(char::is_whitespace) {
        return Err(invalid("external links must be absolute HTTPS URLs"));
    }
    Ok(())
}

fn validate_relative_source_path(value: &str) -> Result<()> {
    validate_text("source path", value)?;
    if value.starts_with('/')
        || value.split('/').any(|segment| {
            segment.is_empty() || segment == "." || segment == ".." || segment.contains('\\')
        })
    {
        return Err(invalid(format!(
            "source path '{value}' is not repository-relative"
        )));
    }
    Ok(())
}

fn find_store_reference(bytes: &[u8]) -> bool {
    bytes
        .windows(b"/nix/store/".len())
        .any(|window| window == b"/nix/store/")
}

fn invalid(message: impl Into<String>) -> DocumentationError {
    DocumentationError::Invalid(message.into())
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn search_row<'a, const N: usize>(
    kind: &str,
    key: &str,
    title: &str,
    summary: &str,
    sources: [(&'a str, u16); N],
) -> SearchDocument {
    let mut terms: BTreeMap<String, u16> = BTreeMap::new();
    for (source, weight) in sources {
        for term in tokenize(source) {
            terms
                .entry(term)
                .and_modify(|existing| *existing = (*existing).max(weight))
                .or_insert(weight);
        }
    }
    SearchDocument {
        kind: kind.to_string(),
        key: key.to_string(),
        title: title.to_string(),
        summary: summary.chars().take(1024).collect(),
        terms,
    }
}

/// Tokenizes text into deterministic lowercase ASCII search terms.
pub fn tokenize(input: &str) -> Vec<String> {
    let mut terms = BTreeSet::new();
    let normalized = input.to_lowercase();
    for token in normalized
        .split(|character: char| !character.is_alphanumeric())
        .filter(|token| token.len() >= 2 && token.len() <= 64)
    {
        terms.insert(token.to_string());
    }
    terms.into_iter().take(2048).collect()
}

fn prose_plain_text(blocks: &[ProseBlock]) -> String {
    let mut output = String::new();
    render_blocks_plain(blocks, &mut output, 0);
    output.trim().to_string()
}

fn render_blocks_plain(blocks: &[ProseBlock], output: &mut String, depth: usize) {
    for block in blocks {
        match block {
            ProseBlock::Paragraph { spans } => {
                render_spans_plain(spans, output);
                output.push_str("\n\n");
            }
            ProseBlock::List { ordered, items } => {
                for (index, item) in items.iter().enumerate() {
                    output.push_str(&"  ".repeat(depth));
                    if *ordered {
                        output.push_str(&format!("{}. ", index + 1));
                    } else {
                        output.push_str("- ");
                    }
                    render_blocks_plain(item, output, depth + 1);
                }
            }
            ProseBlock::Code { text, .. } => {
                for line in text.lines() {
                    output.push_str("    ");
                    output.push_str(line);
                    output.push('\n');
                }
                output.push('\n');
            }
            ProseBlock::Note { severity, blocks } => {
                output.push_str(&format!("{:?}: ", severity).to_uppercase());
                render_blocks_plain(blocks, output, depth + 1);
            }
            ProseBlock::Definitions { entries } => {
                for entry in entries {
                    output.push_str(&entry.term);
                    output.push_str(":\n");
                    render_blocks_plain(&entry.body, output, depth + 1);
                }
            }
        }
    }
}

fn render_spans_plain(spans: &[InlineSpan], output: &mut String) {
    for span in spans {
        match span {
            InlineSpan::Text { text } => output.push_str(text),
            InlineSpan::Code { text } => {
                output.push('`');
                output.push_str(text);
                output.push('`');
            }
            InlineSpan::Link { label, target } => {
                output.push_str(label);
                if let LinkTarget::Https { url } = target {
                    output.push_str(" (");
                    output.push_str(url);
                    output.push(')');
                }
            }
        }
    }
}

fn render_blocks_html(blocks: &[ProseBlock], output: &mut String) {
    for block in blocks {
        match block {
            ProseBlock::Paragraph { spans } => {
                output.push_str("<p>");
                for span in spans {
                    match span {
                        InlineSpan::Text { text } => escape_html_into(text, output),
                        InlineSpan::Code { text } => {
                            output.push_str("<code>");
                            escape_html_into(text, output);
                            output.push_str("</code>");
                        }
                        InlineSpan::Link { label, target } => {
                            let href = link_href(target);
                            output.push_str("<a href=\"");
                            escape_html_into(&href, output);
                            output.push_str("\">");
                            escape_html_into(label, output);
                            output.push_str("</a>");
                        }
                    }
                }
                output.push_str("</p>");
            }
            ProseBlock::List { ordered, items } => {
                let tag = if *ordered { "ol" } else { "ul" };
                output.push_str(&format!("<{tag}>"));
                for item in items {
                    output.push_str("<li>");
                    render_blocks_html(item, output);
                    output.push_str("</li>");
                }
                output.push_str(&format!("</{tag}>"));
            }
            ProseBlock::Code { language, text } => {
                output.push_str("<pre><code data-language=\"");
                escape_html_into(language, output);
                output.push_str("\">");
                escape_html_into(text, output);
                output.push_str("</code></pre>");
            }
            ProseBlock::Note { severity, blocks } => {
                output.push_str("<aside data-severity=\"");
                output.push_str(match severity {
                    NoteSeverity::Info => "info",
                    NoteSeverity::Warning => "warning",
                    NoteSeverity::Security => "security",
                });
                output.push_str("\">");
                render_blocks_html(blocks, output);
                output.push_str("</aside>");
            }
            ProseBlock::Definitions { entries } => {
                output.push_str("<dl>");
                for entry in entries {
                    output.push_str("<dt>");
                    escape_html_into(&entry.term, output);
                    output.push_str("</dt><dd>");
                    render_blocks_html(&entry.body, output);
                    output.push_str("</dd>");
                }
                output.push_str("</dl>");
            }
        }
    }
}

fn link_href(target: &LinkTarget) -> String {
    match target {
        LinkTarget::Package { package } => format!("./{package}"),
        LinkTarget::Option { path } => format!(
            "#option-{}",
            path.iter()
                .map(PathSegment::display)
                .collect::<Vec<_>>()
                .join(".")
        ),
        LinkTarget::Section { id } => format!("#{id}"),
        LinkTarget::Source { path } => format!("./source/{path}"),
        LinkTarget::Https { url } => url.clone(),
    }
}

fn escape_html_into(input: &str, output: &mut String) {
    for character in input.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&#39;"),
            _ => output.push(character),
        }
    }
}

fn render_blocks_roff(blocks: &[ProseBlock], output: &mut String) {
    for block in blocks {
        match block {
            ProseBlock::Paragraph { spans } => {
                output.push_str(".PP\n");
                let mut plain = String::new();
                render_spans_plain(spans, &mut plain);
                escape_roff_into(&plain, output);
                output.push('\n');
            }
            ProseBlock::List { ordered, items } => {
                for (index, item) in items.iter().enumerate() {
                    output.push_str(".IP \"");
                    if *ordered {
                        output.push_str(&format!("{}.", index + 1));
                    } else {
                        output.push_str("\\[bu]");
                    }
                    output.push_str("\" 2\n");
                    render_blocks_roff(item, output);
                }
            }
            ProseBlock::Code { text, .. } => {
                output.push_str(".nf\n");
                escape_roff_into(text, output);
                output.push_str("\n.fi\n");
            }
            ProseBlock::Note { severity, blocks } => {
                output.push_str(".SS \"");
                output.push_str(&format!("{:?}", severity).to_uppercase());
                output.push_str("\"\n");
                render_blocks_roff(blocks, output);
            }
            ProseBlock::Definitions { entries } => {
                for entry in entries {
                    output.push_str(".TP\n.B \"");
                    escape_roff_into(&entry.term, output);
                    output.push_str("\"\n");
                    render_blocks_roff(&entry.body, output);
                }
            }
        }
    }
}

fn escape_roff_into(input: &str, output: &mut String) {
    for line in input.lines() {
        if line.starts_with('.') || line.starts_with('\'') {
            output.push_str("\\&");
        }
        for character in line.chars() {
            if character == '\\' {
                output.push_str("\\e");
            } else {
                output.push(character);
            }
        }
        output.push('\n');
    }
    if !input.ends_with('\n') && output.ends_with('\n') {
        output.pop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paragraph(text: &str) -> ProseBlock {
        ProseBlock::Paragraph {
            spans: vec![InlineSpan::Text {
                text: text.to_string(),
            }],
        }
    }

    fn fixture() -> PackageDocumentation {
        let mut document = PackageDocumentation {
            schema: DOCUMENT_SCHEMA.to_string(),
            package: DocumentedPackage {
                name: "nginx".to_string(),
                version: "1.30.4".to_string(),
                platform: "x86_64-linux".to_string(),
                summary: "HTTP and reverse proxy service".to_string(),
                homepage: Some("https://nginx.org/".to_string()),
                license: "BSD-2-Clause".to_string(),
            },
            identity: DocumentationIdentity {
                semantic_schema_sha256: format!("sha256:{}", "0".repeat(64)),
                runtime_nar_hash: format!("sha256:{}", "1".repeat(64)),
                config_module_nar_hash: Some(format!("sha256:{}", "2".repeat(64))),
                expose_artifact_nar_hash: Some(format!("sha256:{}", "3".repeat(64))),
                source_nar_hash: format!("sha256:{}", "4".repeat(64)),
            },
            sections: vec![Section {
                id: "overview".to_string(),
                title: "Overview".to_string(),
                blocks: vec![paragraph("Configure virtual hosts and upstreams.")],
            }],
            options: vec![OptionDocument {
                path: vec![
                    PathSegment::Literal {
                        value: "nginx".to_string(),
                    },
                    PathSegment::Literal {
                        value: "virtualHosts".to_string(),
                    },
                    PathSegment::Wildcard {
                        name: "name".to_string(),
                    },
                    PathSegment::Literal {
                        value: "listenPort".to_string(),
                    },
                ],
                display_path: "nginx.virtualHosts.<name>.listenPort".to_string(),
                option_type: OptionType::Port,
                type_signature: "unsigned 16-bit TCP port".to_string(),
                description: vec![paragraph("Port on which this virtual host listens.")],
                default: Some(DocumentedValue::Literal {
                    value: Value::from(80),
                }),
                example: Some(DocumentedValue::Literal {
                    value: Value::from(8080),
                }),
                visibility: Visibility::Public,
                read_only: false,
                deprecated: None,
                replacement: None,
                owner: OptionOwner {
                    package: "nginx".to_string(),
                    root: "nginx".to_string(),
                    interface_abi: Some(1),
                },
                contributable: true,
                activation: Some(ActivationEffect {
                    kind: ActivationKind::Reload,
                    units: vec!["nginx.service".to_string()],
                }),
                source: Some(SourceLocator {
                    path: "pkgs/networking/_nginx-config/module.nix".to_string(),
                    attribute: None,
                    line: None,
                }),
            }],
            runtime: RuntimeSurface::default(),
        };
        document.identity.semantic_schema_sha256 = document
            .computed_semantic_schema_sha256()
            .expect("semantic digest");
        document
    }

    #[test]
    fn canonical_round_trip_and_digest_are_stable() {
        let document = fixture();
        document.verify_semantic_schema_sha256().expect("schema");
        let bytes = document.canonical_json().expect("encode");
        let parsed = PackageDocumentation::from_canonical_json(&bytes).expect("decode");
        assert_eq!(parsed, document);
        assert_eq!(parsed.document_sha256().expect("digest").len(), 71);
    }

    #[test]
    fn prose_does_not_change_semantic_digest() {
        let mut document = fixture();
        let before = document
            .computed_semantic_schema_sha256()
            .expect("digest before");
        document.sections[0].blocks = vec![paragraph("Corrected explanation.")];
        document.options[0].description = vec![paragraph("Corrected option prose.")];
        let after = document
            .computed_semantic_schema_sha256()
            .expect("digest after");
        assert_eq!(before, after);
        assert_ne!(
            fixture().document_sha256().expect("old document"),
            document.document_sha256().expect("new document")
        );
    }

    #[test]
    fn semantic_change_updates_digest() {
        let document = fixture();
        let before = document
            .computed_semantic_schema_sha256()
            .expect("digest before");
        let mut changed = document;
        changed.options[0].option_type = OptionType::Unsigned {
            min: Some(1),
            max: Some(65535),
        };
        let after = changed
            .computed_semantic_schema_sha256()
            .expect("digest after");
        assert_ne!(before, after);
    }

    #[test]
    fn rejects_unknown_fields_noncanonical_and_store_paths() {
        let document = fixture();
        let mut value = serde_json::to_value(&document).expect("value");
        value["unknown"] = Value::Bool(true);
        let bytes = serde_json::to_vec(&value).expect("json");
        assert!(PackageDocumentation::from_canonical_json(&bytes).is_err());

        let pretty = serde_json::to_vec_pretty(&document).expect("pretty");
        assert!(PackageDocumentation::from_canonical_json(&pretty).is_err());

        let mut poisoned = fixture();
        poisoned.package.summary = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-secret".into();
        assert!(poisoned.canonical_json().is_err());
    }

    #[test]
    fn renderers_escape_untrusted_content() {
        let mut document = fixture();
        document.package.summary = "<script>alert('x')</script>".into();
        document.sections[0].blocks = vec![paragraph(".danger \\ macro")];
        let html = document.render_html();
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;"));
        let roff = document.render_roff();
        assert!(roff.contains("\\&.danger \\e macro"));
    }

    #[test]
    fn search_projection_is_deterministic() {
        let document = fixture();
        let first = document.search_documents();
        let second = document.search_documents();
        assert_eq!(first, second);
        assert!(first.iter().any(|row| {
            row.kind == "option"
                && row.terms.contains_key("listenport")
                && row.terms.contains_key("virtualhosts")
        }));
    }

    #[test]
    fn checked_json_schema_exposes_the_complete_tooling_contract() {
        let schema: Value = serde_json::from_str(DOCUMENT_JSON_SCHEMA).expect("valid JSON Schema");
        assert_eq!(
            schema
                .pointer("/properties/schema/const")
                .and_then(Value::as_str),
            Some(DOCUMENT_SCHEMA)
        );
        assert_eq!(
            schema
                .pointer("/$defs/optionType/oneOf")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(17)
        );
        for runtime_field in [
            "units",
            "listeners",
            "managed_paths",
            "config_artifacts",
            "credentials",
            "capabilities",
            "confinement",
        ] {
            assert!(
                schema
                    .pointer(&format!("/$defs/runtime/properties/{runtime_field}"))
                    .is_some()
            );
        }
        assert_eq!(
            schema
                .pointer("/$defs/runtime/additionalProperties")
                .and_then(Value::as_bool),
            Some(false)
        );
    }
}
