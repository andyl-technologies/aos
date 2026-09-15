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
use std::fmt::Write as _;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub use aos_ability_model::{
    AbilityValue, DocumentedValue, OptionEnumValue as EnumValue, OptionSource as SourceLocator,
    OptionType, OptionVisibility as Visibility, RelativePath,
};

mod ability_deployment;
mod ability_nar;
mod ability_reference;
mod nar;

pub use ability_deployment::{
    ability_deployment_supported_features, AbilityDeploymentExport, AbilityDeploymentObservation,
    AbilityDeploymentObservationState, AbilityDeploymentPackage, AbilityDeploymentPlan,
    AbilityDeploymentPlanState, PackageAbilityDeploymentOverlay, ABILITY_DEPLOYMENT_OVERLAY_SCHEMA,
    MAX_ABILITY_DEPLOYMENT_OVERLAY_BYTES, MAX_ABILITY_DEPLOYMENT_VALID_FOR_SECONDS,
};
pub use ability_nar::{
    decode_package_ability_nar, PackageAbilityDocuments, MAX_PACKAGE_ABILITY_NAR_BYTES,
};
pub use ability_reference::{
    ability_reference_supported_features, AbilityExportReference, AbilityHandlerReference,
    PackageAbilityReference, ABILITY_REFERENCE_PROVIDER_REQUIREMENTS_V1, ABILITY_REFERENCE_SCHEMA,
    MAX_ABILITY_REFERENCE_BYTES,
};
pub use nar::decode_single_file_nar;

/// Returns the stable HTML anchor for a documentation search kind and key.
///
/// Both strings use lossless UTF-8 hex encoding, so punctuation and kind
/// boundaries cannot collide. The colon namespace cannot overlap validated
/// author-supplied section IDs, which accept only safe token characters.
#[must_use]
pub fn documentation_anchor(kind: &str, key: &str) -> String {
    let mut anchor = String::from("doc");
    for value in [kind, key] {
        anchor.push(':');
        for byte in value.bytes() {
            let _ = write!(anchor, "{byte:02x}");
        }
    }
    anchor
}

/// Canonical schema identifier carried inside every document.
pub const DOCUMENT_SCHEMA: &str = "aos.package-documentation/v1";

/// Media/format identifier advertised by signed registry metadata.
pub const DOCUMENT_FORMAT: &str = "aos.package-documentation/v1+json";

/// Generates the closed JSON Schema served to editors and language tooling.
///
/// The schema is derived from the same Rust data contract that decodes package
/// documentation. This keeps new variants and field changes visible to every
/// frontend without a separately maintained schema snapshot.
///
/// # Errors
///
/// Returns an error if the generated schema cannot be represented as JSON.
pub fn document_json_schema() -> Result<Vec<u8>> {
    let mut schema = serde_json::to_value(schemars::schema_for!(PackageDocumentation))?;
    let schema_property = schema
        .pointer_mut("/properties/schema")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| {
            DocumentationError::Invalid(
                "generated documentation schema omits its schema property".to_string(),
            )
        })?;
    schema_property.insert(
        "const".to_string(),
        Value::String(DOCUMENT_SCHEMA.to_string()),
    );

    Ok(serde_json::to_vec_pretty(&schema)?)
}

/// Maximum canonical document size admitted by version 1.
pub const MAX_DOCUMENT_BYTES: usize = 4 * 1024 * 1024;

const MAX_OPTIONS: usize = 16_384;
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PackageDocumentation {
    /// Closed document schema identifier.
    pub schema: String,
    /// Package selection described by this object.
    pub package: DocumentedPackage,
    /// Content and cross-artifact identities without store paths.
    pub identity: DocumentationIdentity,
}

/// Transient package documentation view derived from one metadata document and
/// its checked signed package ability projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageDocumentationProjection {
    /// Retains the separately signed package metadata document.
    pub document: PackageDocumentation,
    /// Retains the checked package ability reference when the package publishes one.
    pub ability_reference: Option<PackageAbilityReference>,
    /// Carries public option rows derived from the checked package projection.
    pub options: Vec<OptionDocument>,
}

/// Package identity and short catalog metadata embedded in a document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
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

/// Closed structured-prose block understood by every renderer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DefinitionEntry {
    /// Plain-text term.
    pub term: String,
    /// Structured definition body.
    pub body: Vec<ProseBlock>,
}

/// One exact or dynamic option-path segment.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
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

/// Authenticated owner of an option path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
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

/// One mechanically extracted option document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
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
    /// Declaration source locator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<SourceLocator>,
}

/// One deterministic search row derived from a canonical document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchDocument {
    /// Result kind (`package` or `option`).
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

/// Deterministic semantic comparison between two exact package documents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentationComparison {
    /// Compared package name.
    pub package: String,
    /// Exact source version.
    pub from_version: String,
    /// Exact destination version.
    pub to_version: String,
    /// Whether the semantic schema digest changed.
    pub semantic_changed: bool,
    /// Sorted option additions, removals, and semantic modifications.
    pub option_changes: Vec<OptionChange>,
}

/// One option-level semantic change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OptionChange {
    /// Stable human option path.
    pub path: String,
    /// Change classification.
    pub kind: OptionChangeKind,
    /// Previous type signature when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_type: Option<String>,
    /// Destination type signature when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_type: Option<String>,
}

/// Closed option comparison classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OptionChangeKind {
    /// Option exists only in the destination document.
    Added,
    /// Option exists only in the source document.
    Removed,
    /// Configuration meaning changed while the path remained present.
    Changed,
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
        let projection = SemanticProjection {
            package: &self.package.name,
            platform: &self.package.platform,
        };
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
        let mut rows = Vec::with_capacity(1);
        rows.push(search_row(
            "package",
            &self.package.name,
            &self.package.name,
            &self.package.summary,
            [(&self.package.name, 100), (&self.package.summary, 30)],
        ));
        rows
    }

    /// Compares configuration meaning with another exact package document.
    ///
    /// Explanatory prose and source locations do not produce option changes;
    /// the comparison follows the same semantic projection as
    /// [`Self::computed_semantic_schema_sha256`].
    ///
    /// # Errors
    ///
    /// Returns an error when the documents describe different packages or
    /// platforms, or when either document is invalid.
    pub fn compare(&self, other: &Self) -> Result<DocumentationComparison> {
        self.validate()?;
        other.validate()?;
        if self.package.name != other.package.name {
            return Err(DocumentationError::Invalid(format!(
                "cannot compare package '{}' with '{}'",
                self.package.name, other.package.name
            )));
        }
        if self.package.platform != other.package.platform {
            return Err(DocumentationError::Invalid(format!(
                "cannot compare platform '{}' with '{}'",
                self.package.platform, other.package.platform
            )));
        }

        Ok(DocumentationComparison {
            package: self.package.name.clone(),
            from_version: self.package.version.clone(),
            to_version: other.package.version.clone(),
            semantic_changed: self.identity.semantic_schema_sha256
                != other.identity.semantic_schema_sha256,
            option_changes: Vec::new(),
        })
    }

    /// Renders complete, escape-free plain text suitable for terminals.
    pub fn render_plain(&self) -> String {
        let output = format!(
            "{} {} ({})\n{}\n",
            self.package.name, self.package.version, self.package.platform, self.package.summary
        );
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
        output.push_str("<main class=\"package-documentation\"><header id=\"");
        output.push_str(&documentation_anchor("package", &self.package.name));
        output.push_str("\"><h1>");
        escape_html_into(&self.package.name, output);
        output.push_str("</h1><p>");
        escape_html_into(&self.package.summary, output);
        output.push_str("</p><p><code>");
        escape_html_into(&self.package.version, output);
        output.push_str(" · ");
        escape_html_into(&self.package.platform, output);
        output.push_str("</code></p></header>");
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
        output
    }

    fn validate_without_semantic_identity(&self) -> Result<()> {
        let mut copy = self.clone();
        copy.identity.semantic_schema_sha256 = format!("sha256:{}", "0".repeat(64));
        copy.validate()
    }
}

impl PackageDocumentationProjection {
    /// Constructs the one shared renderer/editor view for a package selection.
    ///
    /// # Errors
    ///
    /// Returns an error when either input is invalid or the checked ability
    /// reference belongs to a different package selection.
    pub fn new(
        document: PackageDocumentation,
        ability_reference: Option<PackageAbilityReference>,
    ) -> Result<Self> {
        document.validate()?;
        if let Some(reference) = &ability_reference {
            reference.validate()?;
            if reference.package.as_str() != document.package.name
                || reference.version != document.package.version
            {
                return Err(invalid(
                    "package metadata and ability reference coordinates differ",
                ));
            }
        }

        let options = ability_reference
            .as_ref()
            .map_or_else(Vec::new, PackageAbilityReference::documented_options);
        if options.len() > MAX_OPTIONS {
            return Err(invalid("too many projected options"));
        }
        let mut option_paths = BTreeSet::new();
        for option in &options {
            validate_option(option)?;
            if !option_paths.insert(option.display_path.as_str()) {
                return Err(invalid(format!(
                    "duplicate projected option '{}'",
                    option.display_path
                )));
            }
        }

        Ok(Self {
            document,
            ability_reference,
            options,
        })
    }

    /// Derives deterministic bounded package and option search rows.
    #[must_use]
    pub fn search_documents(&self) -> Vec<SearchDocument> {
        let mut rows = self.document.search_documents();
        rows.reserve(self.options.len());
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
        rows
    }

    /// Compares package option meaning with another checked derived view.
    ///
    /// # Errors
    ///
    /// Returns an error when the views describe different packages or platforms.
    pub fn compare(&self, other: &Self) -> Result<DocumentationComparison> {
        if self.document.package.name != other.document.package.name {
            return Err(invalid(format!(
                "cannot compare package '{}' with '{}'",
                self.document.package.name, other.document.package.name
            )));
        }
        if self.document.package.platform != other.document.package.platform {
            return Err(invalid(format!(
                "cannot compare platform '{}' with '{}'",
                self.document.package.platform, other.document.package.platform
            )));
        }

        let before = self
            .options
            .iter()
            .map(|option| (option.display_path.as_str(), option))
            .collect::<BTreeMap<_, _>>();
        let after = other
            .options
            .iter()
            .map(|option| (option.display_path.as_str(), option))
            .collect::<BTreeMap<_, _>>();
        let paths = before
            .keys()
            .chain(after.keys())
            .copied()
            .collect::<BTreeSet<_>>();
        let mut option_changes = Vec::new();
        for path in paths {
            let change = match (before.get(path), after.get(path)) {
                (None, Some(option)) => Some(OptionChange {
                    path: path.to_string(),
                    kind: OptionChangeKind::Added,
                    from_type: None,
                    to_type: Some(option.type_signature.clone()),
                }),
                (Some(option), None) => Some(OptionChange {
                    path: path.to_string(),
                    kind: OptionChangeKind::Removed,
                    from_type: Some(option.type_signature.clone()),
                    to_type: None,
                }),
                (Some(left), Some(right)) if semantic_option(left) != semantic_option(right) => {
                    Some(OptionChange {
                        path: path.to_string(),
                        kind: OptionChangeKind::Changed,
                        from_type: Some(left.type_signature.clone()),
                        to_type: Some(right.type_signature.clone()),
                    })
                }
                _ => None,
            };
            if let Some(change) = change {
                option_changes.push(change);
            }
        }

        Ok(DocumentationComparison {
            package: self.document.package.name.clone(),
            from_version: self.document.package.version.clone(),
            to_version: other.document.package.version.clone(),
            semantic_changed: !option_changes.is_empty(),
            option_changes,
        })
    }

    /// Renders package metadata and projected public options as plain text.
    #[must_use]
    pub fn render_plain(&self) -> String {
        let mut output = self.document.render_plain();
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

    /// Renders package metadata and projected public options as safe HTML.
    #[must_use]
    pub fn render_html(&self) -> String {
        let mut output = String::from(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>",
        );
        escape_html_into(&self.document.package.name, &mut output);
        output.push_str(" documentation</title></head><body>");
        output.push_str(&self.render_html_fragment());
        output.push_str("</body></html>");
        output
    }

    /// Renders package metadata and projected public options as an embeddable fragment.
    #[must_use]
    pub fn render_html_fragment(&self) -> String {
        let mut output = self.document.render_html_fragment();
        let closing = "</main>";
        if !self.options.is_empty() && output.ends_with(closing) {
            output.truncate(output.len() - closing.len());
            output.push_str("<section id=\"options\"><h2>Options</h2><dl>");
            for option in &self.options {
                output.push_str("<dt id=\"");
                output.push_str(&documentation_anchor("option", &option.display_path));
                output.push_str("\"><code>");
                escape_html_into(&option.display_path, &mut output);
                output.push_str("</code></dt><dd><p><strong>");
                escape_html_into(&option.type_signature, &mut output);
                output.push_str("</strong></p>");
                render_blocks_html(&option.description, &mut output);
                output.push_str("</dd>");
            }
            output.push_str("</dl></section></main>");
        }
        output
    }

    /// Renders package metadata and projected public options as safe roff.
    #[must_use]
    pub fn render_roff(&self) -> String {
        let mut output = self.document.render_roff();
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
}

#[derive(Serialize)]
struct SemanticProjection<'a> {
    package: &'a str,
    platform: &'a str,
}

#[derive(PartialEq, Eq, Serialize)]
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
}

fn semantic_option(option: &OptionDocument) -> SemanticOption<'_> {
    SemanticOption {
        path: &option.path,
        option_type: &option.option_type,
        type_signature: &option.type_signature,
        visibility: option.visibility,
        read_only: option.read_only,
        deprecated: &option.deprecated,
        replacement: &option.replacement,
        owner: &option.owner,
        contributable: option.contributable,
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
    validate_option_type(&option.option_type)?;
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
        validate_relative_source_path(source.path.as_str())?;
    }
    Ok(())
}

fn validate_option_type(option_type: &OptionType) -> Result<()> {
    if option_type.is_within_limits(&aos_ability_model::ABILITY_LIMITS_V1) {
        Ok(())
    } else {
        Err(invalid("option type exceeds the canonical ability limits"))
    }
}

fn validate_documented_value(value: &DocumentedValue) -> Result<()> {
    match value {
        DocumentedValue::Literal { value } => {
            let mut items = 0;
            validate_literal(value.as_json(), 0, &mut items)
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
        Value::String(text) => validate_literal_text("literal string", text),
        Value::Array(values) => {
            for value in values {
                validate_literal(value, depth + 1, items)?;
            }
            Ok(())
        }
        Value::Object(values) => {
            for (key, value) in values {
                validate_literal_text("literal key", key)?;
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
                LinkTarget::Source { path } => validate_relative_source_path(path),
                LinkTarget::Https { url } => validate_https(url),
            }
        }
    }
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
    validate_safe_text(label, value)
}

fn validate_literal_text(label: &str, value: &str) -> Result<()> {
    if value.len() > MAX_TEXT_BYTES {
        return Err(invalid(format!("{label} is too large")));
    }
    validate_safe_text(label, value)
}

fn validate_safe_text(label: &str, value: &str) -> Result<()> {
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
    use aos_ability_model::LocalKey;

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
        };
        document.identity.semantic_schema_sha256 = document
            .computed_semantic_schema_sha256()
            .expect("semantic digest");
        document
    }

    fn option_fixture() -> OptionDocument {
        OptionDocument {
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
                    value: aos_ability_model::AbilityValue::new(Value::from(80))
                        .expect("valid default"),
                }),
                example: Some(DocumentedValue::Literal {
                    value: aos_ability_model::AbilityValue::new(Value::from(8080))
                        .expect("valid example"),
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
                source: Some(SourceLocator {
                    path: aos_ability_model::RelativePath::new(
                        "pkgs/networking/_nginx-config/module.nix",
                    )
                    .expect("valid source path"),
                }),
            }
    }

    fn projection_fixture() -> PackageDocumentationProjection {
        PackageDocumentationProjection {
            document: fixture(),
            ability_reference: None,
            options: vec![option_fixture()],
        }
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
    fn literal_values_preserve_empty_strings_and_attribute_names() {
        let mut option = option_fixture();
        option.default = Some(DocumentedValue::Literal {
            value: aos_ability_model::AbilityValue::new(
                serde_json::json!({"": "", "nested": [""]}),
            )
            .expect("valid literal"),
        });
        let bytes = serde_json::to_vec(&option).expect("encode option");
        let parsed: OptionDocument = serde_json::from_slice(&bytes).expect("decode option");
        assert_eq!(parsed.default, option.default);
    }

    #[test]
    fn prose_does_not_change_semantic_digest() {
        let mut document = fixture();
        let before = document
            .computed_semantic_schema_sha256()
            .expect("digest before");
        document.package.summary = "Corrected package prose.".to_string();
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
    fn comparison_ignores_version_and_prose_but_reports_option_semantics() {
        let before = projection_fixture();
        let mut prose_only = before.clone();
        prose_only.document.package.version = "2.0.0".to_string();
        prose_only.document.package.summary = "New prose".to_string();
        prose_only.document.identity.semantic_schema_sha256 = prose_only
            .document
            .computed_semantic_schema_sha256()
            .expect("semantic digest");
        assert_eq!(
            before.document.identity.semantic_schema_sha256,
            prose_only.document.identity.semantic_schema_sha256
        );
        let comparison = before.compare(&prose_only).expect("comparison");
        assert!(!comparison.semantic_changed);
        assert!(comparison.option_changes.is_empty());

        let mut changed = prose_only.clone();
        changed.options[0].option_type = OptionType::Unsigned {
            min: Some(1),
            max: Some(65_535),
        };
        changed.options[0].type_signature = "unsigned integer".to_string();
        let comparison = before.compare(&changed).expect("comparison");
        assert!(comparison.semantic_changed);
        assert_eq!(comparison.option_changes.len(), 1);
        assert_eq!(comparison.option_changes[0].kind, OptionChangeKind::Changed);
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
        let mut projection = projection_fixture();
        projection.document.package.summary = "<script>alert('x')</script>".into();
        projection.options[0].description = vec![paragraph(".danger \\ macro")];
        let html = projection.render_html();
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;"));
        let roff = projection.render_roff();
        assert!(roff.contains("\\&.danger \\e macro"));
    }

    #[test]
    fn documentation_anchors_preserve_punctuation_and_kind_boundaries() {
        assert_eq!(
            documentation_anchor("option", "a.<b>"),
            "doc:6f7074696f6e:612e3c623e"
        );
        let identities = [
            ("option", "a.b"),
            ("option", "a-b"),
            ("option", "a_2eb"),
            ("service", "a.b"),
            ("a:b", "c"),
            ("a", "b:c"),
            ("option", "\"<>&'é"),
        ];
        let anchors = identities.map(|(kind, key)| documentation_anchor(kind, key));
        assert_eq!(anchors.iter().collect::<BTreeSet<_>>().len(), anchors.len());
        for anchor in anchors {
            assert!(anchor
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b':'));
            assert!(validate_token("section id", &anchor).is_err());
        }
    }

    #[test]
    fn search_projection_is_deterministic() {
        let document = projection_fixture();
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
    fn option_types_preserve_every_portable_structured_constructor_and_bound() {
        let portable_map = OptionType::Map {
            key: aos_ability_model::StringConstraint {
                max_length: 48,
                syntax: Some(aos_ability_model::StringSyntax::LocalKeyV1),
            },
            value: Box::new(OptionType::Bool),
            max_entries: 12,
        };
        let portable_map_json = serde_json::to_value(&portable_map).expect("serialize map");

        assert_eq!(portable_map_json["key"]["max_length"], 48);
        assert_eq!(portable_map_json["key"]["syntax"], "local-key-v1");
        assert_eq!(portable_map_json["max_entries"], 12);
        validate_option_type(&portable_map).expect("valid portable map");

        let canonical_list = OptionType::List {
            element: Box::new(OptionType::String {
                max_length: Some(16),
                pattern: None,
            }),
            max_items: Some(8),
            unique: true,
            canonical_order: true,
        };
        let canonical_list_json = serde_json::to_value(&canonical_list).expect("serialize list");

        assert_eq!(canonical_list_json["unique"], true);
        assert_eq!(canonical_list_json["canonical_order"], true);
        validate_option_type(&canonical_list).expect("valid canonical list");

        let document_record = OptionType::DocumentRecord {
            key_max_length: 64,
            fields: BTreeMap::from([("@type".to_string(), OptionType::Bool)]),
            optional_fields: Vec::new(),
        };
        let document_record_json =
            serde_json::to_value(&document_record).expect("serialize document record");

        assert_eq!(document_record_json["key_max_length"], 64);
        assert!(document_record_json["fields"].get("@type").is_some());
        validate_option_type(&document_record).expect("valid document record");

        let record = OptionType::Record {
            fields: BTreeMap::from([
                (LocalKey::new("enabled").expect("field"), OptionType::Bool),
                (
                    LocalKey::new("label").expect("field"),
                    OptionType::String {
                        max_length: Some(32),
                        pattern: None,
                    },
                ),
            ]),
            optional_fields: vec![LocalKey::new("label").expect("optional field")],
        };
        let record_json = serde_json::to_value(&record).expect("serialize record");

        assert_eq!(record_json["optional_fields"][0], "label");
        validate_option_type(&record).expect("valid record");

        let tagged = OptionType::TaggedUnion {
            tag: LocalKey::new("kind").expect("tag"),
            variants: BTreeMap::from([
                (
                    LocalKey::new("disabled").expect("variant"),
                    OptionType::Record {
                        fields: BTreeMap::new(),
                        optional_fields: Vec::new(),
                    },
                ),
                (LocalKey::new("enabled").expect("variant"), record.clone()),
            ]),
        };
        let tagged_json = serde_json::to_value(&tagged).expect("serialize tagged union");

        assert_eq!(tagged_json["tag"], "kind");
        assert!(tagged_json["variants"].get("enabled").is_some());
        validate_option_type(&tagged).expect("valid tagged union");

        let disjoint = OptionType::DisjointUnion {
            variants: vec![
                OptionType::Bool,
                OptionType::Integer {
                    min: Some(-4),
                    max: Some(4),
                },
                OptionType::String {
                    max_length: Some(24),
                    pattern: None,
                },
            ],
        };
        let disjoint_json = serde_json::to_value(&disjoint).expect("serialize disjoint union");

        assert_eq!(disjoint_json["variants"][0]["kind"], "bool");
        assert_eq!(disjoint_json["variants"][1]["kind"], "integer");
        assert_eq!(disjoint_json["variants"][2]["kind"], "string");
        validate_option_type(&disjoint).expect("valid disjoint union");
    }

    #[test]
    fn checked_json_schema_exposes_the_complete_tooling_contract() {
        let bytes = document_json_schema().expect("generate documentation JSON Schema");
        assert_eq!(
            bytes,
            document_json_schema().expect("regenerate documentation JSON Schema")
        );

        let schema: Value = serde_json::from_slice(&bytes).expect("valid JSON Schema");
        assert_eq!(
            schema.get("$schema").and_then(Value::as_str),
            Some("https://json-schema.org/draft/2020-12/schema")
        );
        assert_eq!(
            schema
                .pointer("/properties/schema/const")
                .and_then(Value::as_str),
            Some(DOCUMENT_SCHEMA)
        );
        assert!(schema.pointer("/properties/options").is_none());
        assert!(schema.pointer("/$defs/OptionType").is_none());
        assert_eq!(
            schema
                .pointer("/additionalProperties")
                .and_then(Value::as_bool),
            Some(false)
        );
    }
}
