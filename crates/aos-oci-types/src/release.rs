//! Signed AOS container-release sidecar contracts.
//!
//! A verified registry release may contain one strict sidecar at
//! `containers/v1/index.json`. The signed document binds AOS release identity,
//! the exact OCI index and platform-manifest descriptors, the Nix definition
//! and realized output, and every required evidence referrer:
//!
//! ```json
//! {
//!   "schemaVersion": 1,
//!   "mediaType": "application/vnd.aos.container-release.v1+json",
//!   "identity": {
//!     "release": "1.0.0",
//!     "package": "aos",
//!     "packageVersion": "0.1.0",
//!     "image": "aos"
//!   },
//!   "oci": {
//!     "index": { "mediaType": "application/vnd.oci.image.index.v1+json", "digest": "sha256:...", "size": 512 },
//!     "platformManifests": [
//!       { "mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "sha256:...", "size": 768, "platform": { "architecture": "amd64", "os": "linux" } }
//!     ]
//!   },
//!   "nix": {
//!     "definition": { "attribute": "containerImages.aos", "derivationPath": "/nix/store/...-aos-container.drv" },
//!     "output": { "name": "out", "storePath": "/nix/store/...-aos-container" },
//!     "closure": { "mediaType": "application/vnd.oci.image.manifest.v1+json", "artifactType": "application/vnd.aos.nix-closure.v1+json", "digest": "sha256:...", "size": 640 }
//!   },
//!   "qualification": {
//!     "schema": "aos.container.evidence-qualification/v1",
//!     "mapping": { "complete": true, "unknownPaths": [] },
//!     "correspondingSource": { "complete": true, "unknownPaths": [] },
//!     "licensing": { "complete": true, "unknownPaths": [] },
//!     "readyForVerifiedPublication": true
//!   },
//!   "evidence": {
//!     "sbom": { "mediaType": "application/vnd.oci.image.manifest.v1+json", "artifactType": "application/spdx+json", "digest": "sha256:...", "size": 640 },
//!     "source": { "mediaType": "application/vnd.oci.image.manifest.v1+json", "artifactType": "application/vnd.aos.source-closure.v1+json", "digest": "sha256:...", "size": 640 },
//!     "license": { "mediaType": "application/vnd.oci.image.manifest.v1+json", "artifactType": "application/vnd.aos.license-report.v1+json", "digest": "sha256:...", "size": 640 },
//!     "provenance": { "mediaType": "application/vnd.oci.image.manifest.v1+json", "artifactType": "application/vnd.in-toto+json", "digest": "sha256:...", "size": 640 },
//!     "signature": { "mediaType": "application/vnd.oci.image.manifest.v1+json", "artifactType": "application/vnd.dsse.envelope.v1+json", "digest": "sha256:...", "size": 640 }
//!   }
//! }
//! ```
//!
//! Unlike generic OCI projections, this AOS-owned signed schema rejects
//! unknown fields at every nested object. Descriptors still retain standard
//! OCI annotations, but no unmodelled field may influence signed-release
//! admission without a versioned schema change.

use std::collections::BTreeSet;

use base64::Engine as _;
use serde::{Deserialize, Deserializer, Serialize};

use crate::annotations::Annotations;
use crate::canonical::{parse_bounded, to_canonical_json};
use crate::digest::Sha256Digest;
use crate::error::{Error, Result};
use crate::limits::{
    MAX_CONTAINER_RELEASE_IDENTITY_BYTES, MAX_JSON_BYTES, MAX_NIX_DEFINITION_ATTRIBUTE_BYTES,
    MAX_NIX_OUTPUT_NAME_BYTES, MAX_NIX_STORE_PATH_BYTES, MAX_PLATFORMS_PER_INDEX,
    MAX_REACHABLE_DESCRIPTORS,
};
use crate::media_type::MediaType;
use crate::model::{Descriptor, Platform};

/// Stable registry-relative location of the first container-release sidecar.
pub const CONTAINER_RELEASE_SIDECAR_PATH: &str = "containers/v1/index.json";

/// Schema version carried by [`ContainerRelease`].
pub const CONTAINER_RELEASE_SCHEMA_VERSION: u32 = 1;

/// Schema identifier carried by [`ContainerSignatureInput`].
pub const CONTAINER_SIGNATURE_INPUT_SCHEMA: &str = "aos.container.signature-input/v1";

/// DSSE payload type used for exact AOS container signature-input bytes.
pub const CONTAINER_SIGNATURE_INPUT_MEDIA_TYPE: &str =
    "application/vnd.aos.container.signature-input.v1+json";

/// SSHSIG namespace used when an AOS trust key signs container DSSE PAE bytes.
pub const CONTAINER_DSSE_SIGNATURE_NAMESPACE: &str = "aos-container-signature-dsse-v1";

/// Schema identifier carried by [`ContainerEvidenceQualification`].
pub const CONTAINER_EVIDENCE_QUALIFICATION_SCHEMA: &str = "aos.container.evidence-qualification/v1";

/// Returns whether a Nix definition attribute names the exact logical image.
///
/// Unified system evaluations use
/// `systems.<variant>.build.containers.<image>`. The legacy
/// `containerImages.<image>` alias remains accepted so already-signed sidecars
/// can still be resumed and verified.
#[must_use]
pub fn definition_attribute_matches_image(attribute: &str, image: &str) -> bool {
    if attribute == format!("containerImages.{image}") {
        return true;
    }

    let suffix = format!(".build.containers.{image}");
    attribute
        .strip_prefix("systems.")
        .and_then(|rest| rest.strip_suffix(&suffix))
        .is_some_and(|variant| !variant.is_empty() && !variant.contains('.'))
}

/// One strict signed AOS container-release sidecar.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContainerRelease {
    /// Required AOS sidecar schema version, currently `1`.
    pub schema_version: u32,
    /// Required exact AOS container-release media type.
    pub media_type: MediaType,
    /// Signed registry release, package, and logical image identity.
    pub identity: ContainerReleaseIdentity,
    /// Exact OCI index and per-platform manifest roots.
    pub oci: ContainerOciRelease,
    /// Nix definition, realized output, and closure-manifest identity.
    pub nix: ContainerNixProvenance,
    /// Full-closure mapping, source, and licensing qualification.
    pub qualification: ContainerEvidenceQualification,
    /// Required source, compliance, provenance, and signature evidence.
    pub evidence: ContainerReleaseEvidence,
}

impl ContainerRelease {
    /// Parses and validates one strict signed sidecar within the 4 MiB JSON cap.
    ///
    /// # Errors
    ///
    /// Returns an error when the document is oversized or malformed, contains
    /// an unknown field, or violates [`Self::validate`].
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let release: Self = parse_bounded(bytes, "AOS container release")?;
        release.validate()?;
        Ok(release)
    }

    /// Validates every identity, OCI root, Nix output, and evidence role.
    ///
    /// # Errors
    ///
    /// Returns an error for the wrong schema or media type, invalid or
    /// overlong identities, malformed descriptors, duplicate platforms,
    /// invalid Nix paths, or a missing/mistyped evidence role.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != CONTAINER_RELEASE_SCHEMA_VERSION {
            return Err(Error::invalid(
                "container release schemaVersion",
                format!(
                    "expected {CONTAINER_RELEASE_SCHEMA_VERSION}, got {}",
                    self.schema_version
                ),
            ));
        }
        if self.media_type != MediaType::AosContainerRelease {
            return Err(Error::invalid(
                "container release mediaType",
                format!(
                    "expected {}, got {}",
                    MediaType::AosContainerRelease,
                    self.media_type
                ),
            ));
        }

        self.identity.validate()?;
        self.oci.validate()?;
        self.nix.validate()?;
        self.qualification.validate()?;
        if !self.qualification.ready_for_verified_publication {
            return Err(Error::invalid(
                "container release qualification",
                "readyForVerifiedPublication must be true",
            ));
        }
        self.evidence.validate()?;
        validate_unique_release_descriptors(self)?;
        to_canonical_json(self).map(|_| ())
    }

    /// Parses a sidecar and requires its bytes to use canonical AOS JSON.
    ///
    /// # Errors
    ///
    /// Returns an error under the same conditions as [`Self::from_json`], or
    /// when insignificant whitespace or object-key ordering is non-canonical.
    pub fn from_canonical_json(bytes: &[u8]) -> Result<Self> {
        let release = Self::from_json(bytes)?;
        if to_canonical_json(&release)? != bytes {
            return Err(Error::invalid(
                "container release JSON",
                "document must use canonical JSON",
            ));
        }
        Ok(release)
    }
}

/// Strict unsigned input whose exact bytes are authorized by an external signer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContainerSignatureInput {
    /// Required exact schema identifier.
    pub schema: String,
    /// Release, package, and image identity to carry into the final sidecar.
    pub identity: ContainerReleaseIdentity,
    /// Exact OCI index and per-platform roots to carry into the final sidecar.
    pub oci: ContainerOciRelease,
    /// Exact Nix definition, output, and closure identity.
    pub nix: ContainerNixProvenance,
    /// Unsigned evidence roots emitted by the hermetic Nix build.
    pub evidence: ContainerSignatureInputEvidence,
    /// Full-closure qualification emitted by the hermetic Nix build.
    pub qualification: ContainerEvidenceQualification,
}

impl ContainerSignatureInput {
    /// Parses and validates one strict signature input within the 4 MiB JSON cap.
    ///
    /// # Errors
    ///
    /// Returns an error when the document is oversized or malformed, contains
    /// an unknown field, or violates [`Self::validate`].
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let input: Self = parse_bounded(bytes, "AOS container signature input")?;
        input.validate()?;
        Ok(input)
    }

    /// Parses a signature input and requires canonical AOS JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns an error under the same conditions as [`Self::from_json`], or
    /// when insignificant whitespace or object-key ordering is non-canonical.
    pub fn from_canonical_json(bytes: &[u8]) -> Result<Self> {
        let input = Self::from_json(bytes)?;
        if to_canonical_json(&input)? != bytes {
            return Err(Error::invalid(
                "container signature input JSON",
                "document must use canonical JSON",
            ));
        }
        Ok(input)
    }

    /// Validates the versioned identity, roots, evidence, and qualification.
    ///
    /// This structural check permits an explicitly unqualified input so tools
    /// can diagnose it. Verified publication must additionally use
    /// [`Self::validate_final_release`], which fails closed unless it is ready.
    ///
    /// # Errors
    ///
    /// Returns an error for the wrong schema or for invalid nested contracts.
    pub fn validate(&self) -> Result<()> {
        if self.schema != CONTAINER_SIGNATURE_INPUT_SCHEMA {
            return Err(Error::invalid(
                "container signature input schema",
                format!(
                    "expected {CONTAINER_SIGNATURE_INPUT_SCHEMA}, got {}",
                    self.schema
                ),
            ));
        }
        self.identity.validate()?;
        self.oci.validate()?;
        self.nix.validate()?;
        self.evidence.validate()?;
        self.qualification.validate()?;
        validate_unique_signature_input_descriptors(self)?;
        to_canonical_json(self).map(|_| ())
    }

    /// Requires a ready input and an exact final-sidecar binding.
    ///
    /// The final sidecar may add only the DSSE signature descriptor. Every
    /// unsigned identity, OCI, Nix, evidence, and qualification field must be
    /// byte-model equal to the externally authorized signature input.
    ///
    /// # Errors
    ///
    /// Returns an error when either contract is invalid or unqualified, or
    /// when any unsigned field differs.
    pub fn validate_final_release(&self, release: &ContainerRelease) -> Result<()> {
        self.validate()?;
        release.validate()?;
        if !self.qualification.ready_for_verified_publication {
            return Err(Error::invalid(
                "container signature input qualification",
                "readyForVerifiedPublication must be true",
            ));
        }
        if self.identity != release.identity {
            return Err(Error::invalid(
                "container signature input identity",
                "final sidecar identity differs from the unsigned input",
            ));
        }
        if self.oci != release.oci {
            return Err(Error::invalid(
                "container signature input OCI roots",
                "final sidecar OCI roots differ from the unsigned input",
            ));
        }
        if self.nix != release.nix {
            return Err(Error::invalid(
                "container signature input Nix provenance",
                "final sidecar Nix provenance differs from the unsigned input",
            ));
        }
        if !self.evidence.matches(&release.evidence) {
            return Err(Error::invalid(
                "container signature input evidence",
                "final sidecar unsigned evidence differs from the unsigned input",
            ));
        }
        if self.qualification != release.qualification {
            return Err(Error::invalid(
                "container signature input qualification",
                "final sidecar qualification differs from the unsigned input",
            ));
        }
        Ok(())
    }
}

/// One strict DSSE envelope carrying exact canonical container signature input.
///
/// The payload and signature use canonical padded RFC 4648 base64. Cryptographic
/// verification belongs to the trust-aware Hub layer; this dependency-light
/// model owns the bounded wire shape and DSSE PAE construction shared with the
/// native and Worker paths.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContainerDsseEnvelope {
    /// Exact AOS container signature-input payload media type.
    pub payload_type: String,
    /// Canonical base64 of the exact canonical signature-input JSON bytes.
    pub payload: String,
    /// Exactly one signature made by the release-tag trust identity.
    pub signatures: Vec<ContainerDsseSignature>,
}

impl ContainerDsseEnvelope {
    /// Parses and structurally validates one bounded container DSSE envelope.
    ///
    /// # Errors
    ///
    /// Returns an error when the JSON is oversized, malformed, contains an
    /// unknown field, or violates [`Self::validate`].
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let envelope: Self = parse_bounded(bytes, "AOS container DSSE envelope")?;
        envelope.validate()?;
        Ok(envelope)
    }

    /// Validates the payload type, single signer identity, and base64 encodings.
    ///
    /// # Errors
    ///
    /// Returns an error for the wrong payload type, other than one signature,
    /// an invalid signer identity, or noncanonical/oversized base64 content.
    pub fn validate(&self) -> Result<()> {
        if self.payload_type != CONTAINER_SIGNATURE_INPUT_MEDIA_TYPE {
            return Err(Error::invalid(
                "container DSSE payloadType",
                format!(
                    "expected {CONTAINER_SIGNATURE_INPUT_MEDIA_TYPE}, got {}",
                    self.payload_type
                ),
            ));
        }
        if self.signatures.len() != 1 {
            return Err(Error::invalid(
                "container DSSE signatures",
                "exactly one trusted signature is required",
            ));
        }
        self.signatures[0].validate()?;
        let payload = decode_canonical_base64(&self.payload, "container DSSE payload")?;
        if payload.is_empty() || payload.len() > MAX_JSON_BYTES {
            return Err(Error::invalid(
                "container DSSE payload",
                format!("decoded payload must contain 1..={MAX_JSON_BYTES} bytes"),
            ));
        }
        Ok(())
    }

    /// Decodes and parses the exact canonical signature-input payload.
    ///
    /// # Errors
    ///
    /// Returns an error when the envelope or base64 is invalid, or when the
    /// decoded bytes are not a canonical [`ContainerSignatureInput`].
    pub fn signature_input(&self) -> Result<(Vec<u8>, ContainerSignatureInput)> {
        self.validate()?;
        let bytes = decode_canonical_base64(&self.payload, "container DSSE payload")?;
        let input = ContainerSignatureInput::from_canonical_json(&bytes)?;
        Ok((bytes, input))
    }

    /// Constructs DSSE v1 pre-authentication encoding for the exact payload.
    ///
    /// # Errors
    ///
    /// Returns an error under the same conditions as [`Self::signature_input`].
    pub fn pae(&self) -> Result<Vec<u8>> {
        let (payload, _) = self.signature_input()?;
        let mut pae = Vec::with_capacity(
            payload
                .len()
                .saturating_add(self.payload_type.len())
                .saturating_add(64),
        );
        pae.extend_from_slice(b"DSSEv1 ");
        pae.extend_from_slice(self.payload_type.len().to_string().as_bytes());
        pae.push(b' ');
        pae.extend_from_slice(self.payload_type.as_bytes());
        pae.push(b' ');
        pae.extend_from_slice(payload.len().to_string().as_bytes());
        pae.push(b' ');
        pae.extend_from_slice(&payload);
        Ok(pae)
    }
}

/// One strict signature entry in an AOS container DSSE envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerDsseSignature {
    /// Canonical base64 SSH Ed25519 key blob of the intended release signer.
    pub keyid: String,
    /// Canonical base64 of one armored SSHSIG over the DSSE PAE bytes.
    pub sig: String,
}

impl ContainerDsseSignature {
    /// Decodes the bounded armored SSHSIG bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when this entry is invalid, noncanonical base64, or is
    /// not UTF-8 SSHSIG armor.
    pub fn armored_signature(&self) -> Result<String> {
        self.validate()?;
        let bytes = decode_canonical_base64(&self.sig, "container DSSE signature")?;
        String::from_utf8(bytes).map_err(|error| {
            Error::invalid(
                "container DSSE signature",
                format!("armored SSHSIG is not UTF-8: {error}"),
            )
        })
    }

    fn validate(&self) -> Result<()> {
        let key = decode_canonical_base64(&self.keyid, "container DSSE keyid")?;
        if key.is_empty() || key.len() > 512 {
            return Err(Error::invalid(
                "container DSSE keyid",
                "decoded SSH key identity must contain 1..=512 bytes",
            ));
        }
        let signature = decode_canonical_base64(&self.sig, "container DSSE signature")?;
        if signature.is_empty() || signature.len() > 16 * 1024 {
            return Err(Error::invalid(
                "container DSSE signature",
                "decoded SSHSIG must contain 1..=16384 bytes",
            ));
        }
        Ok(())
    }
}

fn decode_canonical_base64(value: &str, field: &'static str) -> Result<Vec<u8>> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(value.as_bytes())
        .map_err(|error| Error::invalid(field, format!("invalid base64: {error}")))?;
    if base64::engine::general_purpose::STANDARD.encode(&decoded) != value {
        return Err(Error::invalid(
            field,
            "base64 must use canonical padded encoding",
        ));
    }
    Ok(decoded)
}

/// Evidence descriptors present before an external signer adds DSSE evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContainerSignatureInputEvidence {
    /// OCI referrer manifest for the SPDX 2.3 JSON SBOM.
    #[serde(deserialize_with = "deserialize_strict_descriptor")]
    pub sbom: Descriptor,
    /// OCI referrer manifest for the corresponding-source closure.
    #[serde(deserialize_with = "deserialize_strict_descriptor")]
    pub source: Descriptor,
    /// OCI referrer manifest for the full-closure license report.
    #[serde(deserialize_with = "deserialize_strict_descriptor")]
    pub license: Descriptor,
    /// OCI referrer manifest for the versioned in-toto provenance statement.
    #[serde(deserialize_with = "deserialize_strict_descriptor")]
    pub provenance: Descriptor,
}

impl ContainerSignatureInputEvidence {
    /// Validates every unsigned evidence descriptor role.
    ///
    /// # Errors
    ///
    /// Returns an error unless every descriptor is a correctly typed OCI
    /// referrer manifest.
    pub fn validate(&self) -> Result<()> {
        validate_evidence_descriptor(
            &self.sbom,
            "container signature input SBOM",
            MediaType::SpdxJson,
        )?;
        validate_evidence_descriptor(
            &self.source,
            "container signature input source",
            MediaType::AosSourceClosure,
        )?;
        validate_evidence_descriptor(
            &self.license,
            "container signature input license",
            MediaType::AosLicenseReport,
        )?;
        validate_evidence_descriptor(
            &self.provenance,
            "container signature input provenance",
            MediaType::InTotoJson,
        )
    }

    fn matches(&self, evidence: &ContainerReleaseEvidence) -> bool {
        self.sbom == evidence.sbom
            && self.source == evidence.source
            && self.license == evidence.license
            && self.provenance == evidence.provenance
    }
}

/// Full-closure evidence gate shared by Nix, APR, the CLI, and Hub.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContainerEvidenceQualification {
    /// Required exact qualification schema identifier.
    pub schema: String,
    /// Mapping coverage for every runtime closure path.
    pub mapping: ContainerEvidenceMappingQualification,
    /// Corresponding-source coverage for every mapped runtime path.
    pub corresponding_source: ContainerEvidenceQualificationCheck,
    /// License-metadata coverage for every mapped runtime path.
    pub licensing: ContainerEvidenceQualificationCheck,
    /// Whether all three mandatory qualification gates are complete.
    pub ready_for_verified_publication: bool,
}

impl ContainerEvidenceQualification {
    /// Validates the schema, bounded diagnostics, and derived ready state.
    ///
    /// # Errors
    ///
    /// Returns an error when a check is internally inconsistent, diagnostic
    /// paths are duplicated or unsorted, or the ready bit is not exactly the
    /// conjunction of the three completeness bits.
    pub fn validate(&self) -> Result<()> {
        if self.schema != CONTAINER_EVIDENCE_QUALIFICATION_SCHEMA {
            return Err(Error::invalid(
                "container evidence qualification schema",
                format!(
                    "expected {CONTAINER_EVIDENCE_QUALIFICATION_SCHEMA}, got {}",
                    self.schema
                ),
            ));
        }
        self.mapping.validate()?;
        self.corresponding_source
            .validate("container corresponding-source qualification")?;
        self.licensing
            .validate("container licensing qualification")?;
        let expected =
            self.mapping.complete && self.corresponding_source.complete && self.licensing.complete;
        if self.ready_for_verified_publication != expected {
            return Err(Error::invalid(
                "container evidence qualification readyForVerifiedPublication",
                "value must equal mapping.complete && correspondingSource.complete && licensing.complete",
            ));
        }
        Ok(())
    }
}

/// Closure-to-package mapping qualification and its bounded diagnostics.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContainerEvidenceMappingQualification {
    /// Whether every runtime closure path maps to exactly one package.
    pub complete: bool,
    /// Sorted diagnostics for paths without one unambiguous package mapping.
    pub unknown_paths: Vec<ContainerEvidenceMappingUnknownPath>,
}

impl ContainerEvidenceMappingQualification {
    /// Validates completeness, path ordering, and candidate bounds.
    ///
    /// # Errors
    ///
    /// Returns an error when completeness disagrees with the diagnostic list,
    /// paths are unsorted or duplicated, or a diagnostic is invalid.
    pub fn validate(&self) -> Result<()> {
        validate_item_count(
            self.unknown_paths.len(),
            "container mapping qualification unknownPaths",
            MAX_REACHABLE_DESCRIPTORS,
        )?;
        if self.complete != self.unknown_paths.is_empty() {
            return Err(Error::invalid(
                "container mapping qualification complete",
                "complete must be true exactly when unknownPaths is empty",
            ));
        }
        validate_sorted_unique_paths(
            self.unknown_paths.iter().map(|entry| entry.path.as_str()),
            "container mapping qualification unknownPaths",
        )?;
        for entry in &self.unknown_paths {
            entry.validate()?;
        }
        Ok(())
    }
}

/// One path whose evaluated package mapping is missing or ambiguous.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContainerEvidenceMappingUnknownPath {
    /// Exact realized Nix store path that could not be mapped uniquely.
    pub path: String,
    /// Stable qualification reason emitted by the evidence builder.
    pub reason: String,
    /// Deterministically ordered package candidates for an ambiguous path.
    pub candidates: Vec<ContainerEvidencePackageCandidate>,
}

impl ContainerEvidenceMappingUnknownPath {
    fn validate(&self) -> Result<()> {
        validate_store_path(
            &self.path,
            "container mapping qualification unknown path",
            false,
        )?;
        validate_diagnostic_text(
            &self.reason,
            "container mapping qualification unknown reason",
        )?;
        validate_item_count(
            self.candidates.len(),
            "container mapping qualification candidates",
            MAX_PLATFORMS_PER_INDEX,
        )?;
        for candidate in &self.candidates {
            candidate.validate()?;
        }
        Ok(())
    }
}

/// One evaluated AOS package candidate for an ambiguous closure path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContainerEvidencePackageCandidate {
    /// Exact derivation store path for the package definition.
    pub derivation_path: String,
    /// Evaluated package name.
    pub pname: String,
    /// Evaluated package version.
    pub version: String,
    /// Evaluated license identifiers.
    pub licenses: Vec<String>,
    /// Evaluated source identities.
    pub sources: Vec<ContainerEvidenceSourceIdentity>,
    /// Runtime dependency output paths used during evidence selection.
    pub runtime_dependencies: Vec<String>,
    /// Candidate output name and realized path.
    pub output: ContainerEvidencePackageOutput,
}

impl ContainerEvidencePackageCandidate {
    fn validate(&self) -> Result<()> {
        validate_store_path(
            &self.derivation_path,
            "container mapping candidate derivationPath",
            true,
        )?;
        validate_diagnostic_text(&self.pname, "container mapping candidate pname")?;
        validate_diagnostic_text(&self.version, "container mapping candidate version")?;
        validate_item_count(
            self.licenses.len(),
            "container mapping candidate licenses",
            MAX_PLATFORMS_PER_INDEX,
        )?;
        validate_item_count(
            self.sources.len(),
            "container mapping candidate sources",
            MAX_PLATFORMS_PER_INDEX,
        )?;
        validate_item_count(
            self.runtime_dependencies.len(),
            "container mapping candidate runtimeDependencies",
            MAX_REACHABLE_DESCRIPTORS,
        )?;
        for license in &self.licenses {
            validate_diagnostic_text(license, "container mapping candidate license")?;
        }
        for source in &self.sources {
            source.validate()?;
        }
        for dependency in &self.runtime_dependencies {
            validate_store_path(
                dependency,
                "container mapping candidate runtime dependency",
                false,
            )?;
        }
        self.output.validate()
    }
}

/// Evaluated source identity retained for one package candidate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContainerEvidenceSourceIdentity {
    /// Realized source store path.
    pub path: String,
    /// Source derivation path, when the source exposes one.
    pub derivation_path: Option<String>,
    /// Declared upstream source URLs.
    pub urls: Vec<String>,
    /// Declared fixed-output content hash, when available.
    pub content_hash: Option<String>,
}

impl ContainerEvidenceSourceIdentity {
    fn validate(&self) -> Result<()> {
        validate_store_path(&self.path, "container evidence source path", false)?;
        if let Some(derivation_path) = &self.derivation_path {
            validate_store_path(
                derivation_path,
                "container evidence source derivationPath",
                true,
            )?;
        }
        validate_item_count(
            self.urls.len(),
            "container evidence source URLs",
            MAX_PLATFORMS_PER_INDEX,
        )?;
        for url in &self.urls {
            validate_long_text(url, "container evidence source URL")?;
        }
        if let Some(content_hash) = &self.content_hash {
            validate_long_text(content_hash, "container evidence source contentHash")?;
        }
        Ok(())
    }
}

/// Evaluated name and realized path for one package candidate output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContainerEvidencePackageOutput {
    /// Named Nix output, such as `out`.
    pub name: String,
    /// Exact realized Nix store path.
    pub path: String,
}

impl ContainerEvidencePackageOutput {
    fn validate(&self) -> Result<()> {
        validate_nix_output_name(&self.name)?;
        validate_store_path(&self.path, "container mapping candidate output path", false)
    }
}

/// One source or license coverage diagnostic for a runtime closure path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContainerEvidenceUnknownPath {
    /// Exact realized Nix store path that failed the coverage check.
    pub path: String,
    /// Stable qualification reason emitted by the evidence builder.
    pub reason: String,
}

impl ContainerEvidenceUnknownPath {
    fn validate(&self, field: &'static str) -> Result<()> {
        validate_store_path(&self.path, field, false)?;
        validate_diagnostic_text(&self.reason, field)
    }
}

/// One boolean qualification gate and its sorted failure diagnostics.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContainerEvidenceQualificationCheck {
    /// Whether every path passed this evidence gate.
    pub complete: bool,
    /// Sorted diagnostics for paths that failed this gate.
    pub unknown_paths: Vec<ContainerEvidenceUnknownPath>,
}

impl ContainerEvidenceQualificationCheck {
    fn validate(&self, field: &'static str) -> Result<()> {
        validate_item_count(self.unknown_paths.len(), field, MAX_REACHABLE_DESCRIPTORS)?;
        if self.complete != self.unknown_paths.is_empty() {
            return Err(Error::invalid(
                field,
                "complete must be true exactly when unknownPaths is empty",
            ));
        }
        validate_sorted_unique_paths(
            self.unknown_paths.iter().map(|entry| entry.path.as_str()),
            field,
        )?;
        for entry in &self.unknown_paths {
            entry.validate(field)?;
        }
        Ok(())
    }
}

/// Signed AOS identities associated with one immutable container release.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContainerReleaseIdentity {
    /// Signed registry release version containing the sidecar.
    pub release: String,
    /// AOS package whose runtime is represented by the image.
    pub package: String,
    /// Exact AOS package version represented by the image.
    pub package_version: String,
    /// Logical container definition name, initially `aos`.
    pub image: String,
}

impl ContainerReleaseIdentity {
    /// Validates the release, package, package-version, and image identities.
    ///
    /// # Errors
    ///
    /// Returns an error when a field is empty, exceeds 255 bytes, is not
    /// printable ASCII, or a package/image name violates its safe-name syntax.
    pub fn validate(&self) -> Result<()> {
        validate_version_identity(&self.release, "container release identity release")?;
        validate_package_name(&self.package)?;
        validate_version_identity(
            &self.package_version,
            "container release identity packageVersion",
        )?;
        validate_image_name(&self.image)
    }
}

/// Exact OCI roots bound by a signed AOS container release.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContainerOciRelease {
    /// Descriptor of the publishable multi-platform OCI image index.
    #[serde(deserialize_with = "deserialize_strict_descriptor")]
    pub index: Descriptor,
    /// Ordered descriptors of every platform manifest named by the index.
    #[serde(deserialize_with = "deserialize_strict_descriptors")]
    pub platform_manifests: Vec<Descriptor>,
}

impl ContainerOciRelease {
    /// Validates index and platform-manifest roles, sizes, and uniqueness.
    ///
    /// # Errors
    ///
    /// Returns an error unless the index is an OCI index descriptor, one to
    /// 256 OCI manifest descriptors carry valid distinct platforms, manifest
    /// digests are unique, and every JSON descriptor is within 4 MiB.
    pub fn validate(&self) -> Result<()> {
        validate_document_descriptor(
            &self.index,
            "container release OCI index",
            MediaType::OciImageIndex,
            PlatformRequirement::Forbidden,
        )?;

        if self.platform_manifests.is_empty() {
            return Err(Error::invalid(
                "container release platformManifests",
                "at least one platform manifest is required",
            ));
        }
        if self.platform_manifests.len() > MAX_PLATFORMS_PER_INDEX {
            return Err(Error::TooManyItems {
                field: "container release platformManifests",
                limit: MAX_PLATFORMS_PER_INDEX,
                actual: self.platform_manifests.len(),
            });
        }

        let mut manifest_digests = BTreeSet::new();
        for manifest in &self.platform_manifests {
            validate_document_descriptor(
                manifest,
                "container release platform manifest",
                MediaType::OciImageManifest,
                PlatformRequirement::Required,
            )?;
            if !manifest_digests.insert(manifest.digest) {
                return Err(Error::invalid(
                    "container release platformManifests",
                    format!("manifest digest {} is duplicated", manifest.digest),
                ));
            }
        }

        for (index, platform) in self.platform_manifests.iter().enumerate() {
            if self.platform_manifests[..index]
                .iter()
                .any(|candidate| candidate.platform == platform.platform)
            {
                let platform = platform
                    .platform
                    .as_ref()
                    .ok_or_else(|| Error::invalid("container release platform", "missing"))?;
                return Err(Error::invalid(
                    "container release platformManifests",
                    format!("platform {} is duplicated", platform_label(platform)),
                ));
            }
        }
        Ok(())
    }
}

/// Nix definition and realized-output provenance for a container image.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContainerNixProvenance {
    /// Nix attribute and derivation that defined the image.
    pub definition: NixDefinitionIdentity,
    /// Named realized Nix output containing the self-contained OCI image.
    pub output: NixOutputIdentity,
    /// OCI referrer manifest for the realized Nix closure inventory.
    #[serde(deserialize_with = "deserialize_strict_descriptor")]
    pub closure: Descriptor,
}

impl ContainerNixProvenance {
    /// Validates Nix definition/output identity and the closure referrer role.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid attribute, derivation, output name,
    /// output store path, or closure referrer descriptor.
    pub fn validate(&self) -> Result<()> {
        self.definition.validate()?;
        self.output.validate()?;
        validate_evidence_descriptor(
            &self.closure,
            "container release closure",
            MediaType::AosNixClosure,
        )
    }
}

/// Evaluated Nix definition identity for a container image.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NixDefinitionIdentity {
    /// Canonical dotted Nix attribute, such as `containerImages.aos`.
    pub attribute: String,
    /// Exact realized derivation store path that defined the image output.
    pub derivation_path: String,
}

impl NixDefinitionIdentity {
    /// Validates the dotted attribute and derivation store path.
    ///
    /// # Errors
    ///
    /// Returns an error when the attribute is empty, overlong, or contains an
    /// unsafe segment, or when the derivation is not a bounded `.drv` store
    /// path below `/nix/store`.
    pub fn validate(&self) -> Result<()> {
        validate_nix_attribute(&self.attribute)?;
        validate_store_path(
            &self.derivation_path,
            "container release Nix definition derivationPath",
            true,
        )
    }
}

/// Realized Nix output identity for a container image.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NixOutputIdentity {
    /// Selected Nix output name, normally `out`.
    pub name: String,
    /// Exact realized store path of the self-contained OCI image output.
    pub store_path: String,
}

impl NixOutputIdentity {
    /// Validates the output name and realized store path.
    ///
    /// # Errors
    ///
    /// Returns an error when the output name is empty, overlong, or unsafe, or
    /// when the output is not a bounded non-derivation path below `/nix/store`.
    pub fn validate(&self) -> Result<()> {
        validate_nix_output_name(&self.name)?;
        validate_store_path(
            &self.store_path,
            "container release Nix output storePath",
            false,
        )
    }
}

/// Required evidence referrers for a signed AOS container release.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContainerReleaseEvidence {
    /// OCI referrer manifest for the SPDX 2.3 JSON software bill of materials.
    #[serde(deserialize_with = "deserialize_strict_descriptor")]
    pub sbom: Descriptor,
    /// OCI referrer manifest for the corresponding-source closure.
    #[serde(deserialize_with = "deserialize_strict_descriptor")]
    pub source: Descriptor,
    /// OCI referrer manifest for the full-closure license report.
    #[serde(deserialize_with = "deserialize_strict_descriptor")]
    pub license: Descriptor,
    /// OCI referrer manifest for the versioned AOS in-toto provenance statement.
    #[serde(deserialize_with = "deserialize_strict_descriptor")]
    pub provenance: Descriptor,
    /// OCI referrer manifest for the DSSE signature envelope.
    #[serde(deserialize_with = "deserialize_strict_descriptor")]
    pub signature: Descriptor,
}

impl ContainerReleaseEvidence {
    /// Validates all mandatory evidence descriptor roles.
    ///
    /// # Errors
    ///
    /// Returns an error unless every field is an OCI referrer-manifest
    /// descriptor whose `artifactType` exactly matches its required role.
    pub fn validate(&self) -> Result<()> {
        validate_evidence_descriptor(&self.sbom, "container release SBOM", MediaType::SpdxJson)?;
        validate_evidence_descriptor(
            &self.source,
            "container release source",
            MediaType::AosSourceClosure,
        )?;
        validate_evidence_descriptor(
            &self.license,
            "container release license",
            MediaType::AosLicenseReport,
        )?;
        validate_evidence_descriptor(
            &self.provenance,
            "container release provenance",
            MediaType::InTotoJson,
        )?;
        validate_evidence_descriptor(
            &self.signature,
            "container release signature",
            MediaType::DsseEnvelope,
        )
    }
}

#[derive(Clone, Copy)]
enum PlatformRequirement {
    Forbidden,
    Required,
}

fn validate_document_descriptor(
    descriptor: &Descriptor,
    field: &'static str,
    media_type: MediaType,
    platform_requirement: PlatformRequirement,
) -> Result<()> {
    descriptor.validate()?;
    if descriptor.media_type != media_type {
        return Err(Error::invalid(
            field,
            format!(
                "expected mediaType {media_type}, got {}",
                descriptor.media_type
            ),
        ));
    }
    if descriptor.artifact_type.is_some() {
        return Err(Error::invalid(
            field,
            "runnable index and manifest descriptors must not declare artifactType",
        ));
    }
    if descriptor.data.is_some() {
        return Err(Error::invalid(
            field,
            "signed release descriptors must not embed data",
        ));
    }
    match (platform_requirement, descriptor.platform.as_ref()) {
        (PlatformRequirement::Forbidden, Some(_)) => {
            return Err(Error::invalid(
                field,
                "the OCI index descriptor must not declare a platform",
            ));
        }
        (PlatformRequirement::Required, None) => {
            return Err(Error::invalid(
                field,
                "a platform manifest descriptor must declare a platform",
            ));
        }
        (PlatformRequirement::Forbidden, None) | (PlatformRequirement::Required, Some(_)) => {}
    }
    validate_descriptor_json_size(descriptor, field)
}

fn validate_evidence_descriptor(
    descriptor: &Descriptor,
    field: &'static str,
    artifact_type: MediaType,
) -> Result<()> {
    descriptor.validate()?;
    if descriptor.media_type != MediaType::OciImageManifest {
        return Err(Error::invalid(
            field,
            format!(
                "evidence referrer must use mediaType {}, got {}",
                MediaType::OciImageManifest,
                descriptor.media_type
            ),
        ));
    }
    if descriptor.artifact_type != Some(artifact_type) {
        let actual = descriptor
            .artifact_type
            .map_or_else(|| "missing".to_string(), |value| value.to_string());
        return Err(Error::invalid(
            field,
            format!("expected artifactType {artifact_type}, got {actual}"),
        ));
    }
    if descriptor.platform.is_some() {
        return Err(Error::invalid(
            field,
            "evidence referrer descriptors must not declare a platform",
        ));
    }
    if descriptor.data.is_some() {
        return Err(Error::invalid(
            field,
            "signed release descriptors must not embed data",
        ));
    }
    validate_descriptor_json_size(descriptor, field)
}

fn validate_descriptor_json_size(descriptor: &Descriptor, field: &'static str) -> Result<()> {
    if descriptor.size == 0 {
        return Err(Error::invalid(
            field,
            "JSON document descriptor size must be greater than zero",
        ));
    }
    let limit =
        u64::try_from(MAX_JSON_BYTES).map_err(|error| Error::invalid(field, error.to_string()))?;
    if descriptor.size > limit {
        return Err(Error::invalid(
            field,
            format!(
                "descriptor size {} exceeds the {MAX_JSON_BYTES}-byte JSON limit",
                descriptor.size
            ),
        ));
    }
    Ok(())
}

fn validate_unique_release_descriptors(release: &ContainerRelease) -> Result<()> {
    let descriptors = [
        (&release.oci.index, "OCI index"),
        (&release.nix.closure, "closure"),
        (&release.evidence.sbom, "SBOM"),
        (&release.evidence.source, "source"),
        (&release.evidence.license, "license"),
        (&release.evidence.provenance, "provenance"),
        (&release.evidence.signature, "signature"),
    ];
    let mut digests = BTreeSet::new();
    for (descriptor, role) in descriptors {
        if !digests.insert(descriptor.digest) {
            return Err(Error::invalid(
                "container release descriptors",
                format!("{role} reuses descriptor digest {}", descriptor.digest),
            ));
        }
    }
    for descriptor in &release.oci.platform_manifests {
        if !digests.insert(descriptor.digest) {
            return Err(Error::invalid(
                "container release descriptors",
                format!(
                    "platform manifest reuses descriptor digest {}",
                    descriptor.digest
                ),
            ));
        }
    }
    Ok(())
}

fn validate_unique_signature_input_descriptors(input: &ContainerSignatureInput) -> Result<()> {
    let descriptors = [
        (&input.oci.index, "OCI index"),
        (&input.nix.closure, "closure"),
        (&input.evidence.sbom, "SBOM"),
        (&input.evidence.source, "source"),
        (&input.evidence.license, "license"),
        (&input.evidence.provenance, "provenance"),
    ];
    let mut digests = BTreeSet::new();
    for (descriptor, role) in descriptors {
        if !digests.insert(descriptor.digest) {
            return Err(Error::invalid(
                "container signature input descriptors",
                format!("{role} reuses descriptor digest {}", descriptor.digest),
            ));
        }
    }
    for descriptor in &input.oci.platform_manifests {
        if !digests.insert(descriptor.digest) {
            return Err(Error::invalid(
                "container signature input descriptors",
                format!(
                    "platform manifest reuses descriptor digest {}",
                    descriptor.digest
                ),
            ));
        }
    }
    Ok(())
}

fn validate_item_count(actual: usize, field: &'static str, limit: usize) -> Result<()> {
    if actual > limit {
        return Err(Error::TooManyItems {
            field,
            limit,
            actual,
        });
    }
    Ok(())
}

fn validate_sorted_unique_paths<'a>(
    paths: impl Iterator<Item = &'a str>,
    field: &'static str,
) -> Result<()> {
    let mut previous = None;
    for path in paths {
        if previous.is_some_and(|value| value >= path) {
            return Err(Error::invalid(
                field,
                "unknownPaths must be sorted by path without duplicates",
            ));
        }
        previous = Some(path);
    }
    Ok(())
}

fn validate_diagnostic_text(value: &str, field: &'static str) -> Result<()> {
    validate_text(value, field, MAX_CONTAINER_RELEASE_IDENTITY_BYTES)
}

fn validate_long_text(value: &str, field: &'static str) -> Result<()> {
    validate_text(value, field, MAX_NIX_STORE_PATH_BYTES)
}

fn validate_text(value: &str, field: &'static str, limit: usize) -> Result<()> {
    if value.is_empty() {
        return Err(Error::invalid(field, "value must not be empty"));
    }
    if value.len() > limit {
        return Err(Error::invalid(
            field,
            format!("value is {} bytes; the limit is {limit}", value.len()),
        ));
    }
    if value
        .chars()
        .any(|character| character.is_control() && character != '\t')
    {
        return Err(Error::invalid(
            field,
            "value must not contain control characters",
        ));
    }
    Ok(())
}

fn validate_package_name(value: &str) -> Result<()> {
    validate_identity_length(value, "container release identity package")?;
    let valid_start = value
        .bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric());
    let valid_bytes = value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'.' | b'_' | b'=' | b'-')
    });
    if !valid_start || !valid_bytes {
        return Err(Error::invalid(
            "container release identity package",
            "use only ASCII letters, digits, '+', '.', '_', '=' and '-', starting with a letter or digit",
        ));
    }
    Ok(())
}

fn validate_image_name(value: &str) -> Result<()> {
    validate_identity_length(value, "container release identity image")?;
    if !value.bytes().enumerate().all(|(index, byte)| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || (index > 0 && byte == b'-')
    }) || value.ends_with('-')
    {
        return Err(Error::invalid(
            "container release identity image",
            "value must match [a-z0-9][a-z0-9-]*",
        ));
    }
    Ok(())
}

fn validate_version_identity(value: &str, field: &'static str) -> Result<()> {
    validate_identity_length(value, field)?;
    if !value.is_ascii()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
    {
        return Err(Error::invalid(
            field,
            "value must contain non-space printable ASCII only",
        ));
    }
    Ok(())
}

fn validate_identity_length(value: &str, field: &'static str) -> Result<()> {
    if value.is_empty() {
        return Err(Error::invalid(field, "value must not be empty"));
    }
    if value.len() > MAX_CONTAINER_RELEASE_IDENTITY_BYTES {
        return Err(Error::invalid(
            field,
            format!(
                "value is {} bytes; the limit is {MAX_CONTAINER_RELEASE_IDENTITY_BYTES}",
                value.len()
            ),
        ));
    }
    Ok(())
}

fn validate_nix_attribute(value: &str) -> Result<()> {
    let field = "container release Nix definition attribute";
    if value.is_empty() {
        return Err(Error::invalid(field, "value must not be empty"));
    }
    if value.len() > MAX_NIX_DEFINITION_ATTRIBUTE_BYTES {
        return Err(Error::invalid(
            field,
            format!(
                "value is {} bytes; the limit is {MAX_NIX_DEFINITION_ATTRIBUTE_BYTES}",
                value.len()
            ),
        ));
    }
    if value.split('.').any(|segment| {
        segment.is_empty()
            || !segment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'+' | b'-'))
    }) {
        return Err(Error::invalid(
            field,
            "value must be dot-separated non-empty ASCII attribute segments",
        ));
    }
    Ok(())
}

fn validate_nix_output_name(value: &str) -> Result<()> {
    let field = "container release Nix output name";
    if value.is_empty() {
        return Err(Error::invalid(field, "value must not be empty"));
    }
    if value.len() > MAX_NIX_OUTPUT_NAME_BYTES {
        return Err(Error::invalid(
            field,
            format!(
                "value is {} bytes; the limit is {MAX_NIX_OUTPUT_NAME_BYTES}",
                value.len()
            ),
        ));
    }
    if !value
        .bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'+' | b'-'))
    {
        return Err(Error::invalid(
            field,
            "value must contain ASCII letters, digits, '_', '+' or '-', starting with a letter or digit",
        ));
    }
    Ok(())
}

fn validate_store_path(value: &str, field: &'static str, derivation: bool) -> Result<()> {
    if value.len() > MAX_NIX_STORE_PATH_BYTES {
        return Err(Error::invalid(
            field,
            format!(
                "value is {} bytes; the limit is {MAX_NIX_STORE_PATH_BYTES}",
                value.len()
            ),
        ));
    }
    let Some(name) = value.strip_prefix("/nix/store/") else {
        return Err(Error::invalid(field, "value must be below /nix/store"));
    };
    let Some((store_hash, store_name)) = name.split_once('-') else {
        return Err(Error::invalid(
            field,
            "value must contain a canonical Nix store hash and name",
        ));
    };
    const NIX_BASE32: &[u8] = b"0123456789abcdfghijklmnpqrsvwxyz";
    if store_hash.len() != 32 || !store_hash.bytes().all(|byte| NIX_BASE32.contains(&byte)) {
        return Err(Error::invalid(
            field,
            "store hash must contain exactly 32 lowercase Nix base32 characters",
        ));
    }
    if store_name.is_empty()
        || store_name.contains('/')
        || !store_name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'.' | b'_' | b'?' | b'=' | b'-')
        })
    {
        return Err(Error::invalid(
            field,
            "value must contain one safe Nix store basename",
        ));
    }
    if derivation != store_name.ends_with(".drv") {
        let reason = if derivation {
            "derivation path must end in .drv"
        } else {
            "output store path must not end in .drv"
        };
        return Err(Error::invalid(field, reason));
    }
    Ok(())
}

fn platform_label(platform: &Platform) -> String {
    platform.variant.as_ref().map_or_else(
        || format!("{}/{}", platform.os, platform.architecture),
        |variant| format!("{}/{}/{}", platform.os, platform.architecture, variant),
    )
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StrictDescriptor {
    media_type: MediaType,
    digest: Sha256Digest,
    size: u64,
    #[serde(default)]
    urls: Vec<String>,
    #[serde(default)]
    annotations: Annotations,
    #[serde(default)]
    data: Option<String>,
    #[serde(default)]
    artifact_type: Option<MediaType>,
    #[serde(default)]
    platform: Option<StrictPlatform>,
}

impl From<StrictDescriptor> for Descriptor {
    fn from(value: StrictDescriptor) -> Self {
        Self {
            media_type: value.media_type,
            digest: value.digest,
            size: value.size,
            urls: value.urls,
            annotations: value.annotations,
            data: value.data,
            artifact_type: value.artifact_type,
            platform: value.platform.map(Platform::from),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StrictPlatform {
    architecture: String,
    os: String,
    #[serde(rename = "os.version", default)]
    os_version: Option<String>,
    #[serde(rename = "os.features", default)]
    os_features: Vec<String>,
    #[serde(default)]
    variant: Option<String>,
    #[serde(default)]
    features: Vec<String>,
}

impl From<StrictPlatform> for Platform {
    fn from(value: StrictPlatform) -> Self {
        Self {
            architecture: value.architecture,
            os: value.os,
            os_version: value.os_version,
            os_features: value.os_features,
            variant: value.variant,
            features: value.features,
        }
    }
}

fn deserialize_strict_descriptor<'de, D>(
    deserializer: D,
) -> std::result::Result<Descriptor, D::Error>
where
    D: Deserializer<'de>,
{
    StrictDescriptor::deserialize(deserializer).map(Descriptor::from)
}

fn deserialize_strict_descriptors<'de, D>(
    deserializer: D,
) -> std::result::Result<Vec<Descriptor>, D::Error>
where
    D: Deserializer<'de>,
{
    Vec::<StrictDescriptor>::deserialize(deserializer)
        .map(|descriptors| descriptors.into_iter().map(Descriptor::from).collect())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn descriptor(media_type: MediaType, label: &str) -> Descriptor {
        Descriptor {
            media_type,
            digest: Sha256Digest::digest(label.as_bytes()),
            size: u64::try_from(label.len()).expect("fixture size"),
            urls: Vec::new(),
            annotations: Annotations::new(),
            data: None,
            artifact_type: None,
            platform: None,
        }
    }

    fn evidence_descriptor(artifact_type: MediaType, label: &str) -> Descriptor {
        Descriptor {
            artifact_type: Some(artifact_type),
            ..descriptor(MediaType::OciImageManifest, label)
        }
    }

    fn qualification_fixture() -> ContainerEvidenceQualification {
        ContainerEvidenceQualification {
            schema: CONTAINER_EVIDENCE_QUALIFICATION_SCHEMA.to_string(),
            mapping: ContainerEvidenceMappingQualification {
                complete: true,
                unknown_paths: Vec::new(),
            },
            corresponding_source: ContainerEvidenceQualificationCheck {
                complete: true,
                unknown_paths: Vec::new(),
            },
            licensing: ContainerEvidenceQualificationCheck {
                complete: true,
                unknown_paths: Vec::new(),
            },
            ready_for_verified_publication: true,
        }
    }

    fn release_fixture() -> ContainerRelease {
        let mut platform_manifest = descriptor(MediaType::OciImageManifest, "amd64-manifest");
        platform_manifest.platform = Some(Platform::linux_amd64());
        ContainerRelease {
            schema_version: CONTAINER_RELEASE_SCHEMA_VERSION,
            media_type: MediaType::AosContainerRelease,
            identity: ContainerReleaseIdentity {
                release: "1.0.0".to_string(),
                package: "aos".to_string(),
                package_version: "0.1.0".to_string(),
                image: "aos".to_string(),
            },
            oci: ContainerOciRelease {
                index: descriptor(MediaType::OciImageIndex, "index"),
                platform_manifests: vec![platform_manifest],
            },
            nix: ContainerNixProvenance {
                definition: NixDefinitionIdentity {
                    attribute: "containerImages.aos".to_string(),
                    derivation_path:
                        "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-aos-container.drv".to_string(),
                },
                output: NixOutputIdentity {
                    name: "out".to_string(),
                    store_path: "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-aos-container"
                        .to_string(),
                },
                closure: evidence_descriptor(MediaType::AosNixClosure, "closure"),
            },
            qualification: qualification_fixture(),
            evidence: ContainerReleaseEvidence {
                sbom: evidence_descriptor(MediaType::SpdxJson, "sbom"),
                source: evidence_descriptor(MediaType::AosSourceClosure, "source"),
                license: evidence_descriptor(MediaType::AosLicenseReport, "license"),
                provenance: evidence_descriptor(MediaType::InTotoJson, "provenance"),
                signature: evidence_descriptor(MediaType::DsseEnvelope, "signature"),
            },
        }
    }

    fn signature_input_fixture() -> ContainerSignatureInput {
        let release = release_fixture();
        ContainerSignatureInput {
            schema: CONTAINER_SIGNATURE_INPUT_SCHEMA.to_string(),
            identity: release.identity,
            oci: release.oci,
            nix: release.nix,
            evidence: ContainerSignatureInputEvidence {
                sbom: release.evidence.sbom,
                source: release.evidence.source,
                license: release.evidence.license,
                provenance: release.evidence.provenance,
            },
            qualification: release.qualification,
        }
    }

    #[test]
    fn accepts_and_round_trips_the_complete_required_contract() {
        let release = release_fixture();
        release.validate().expect("valid release");
        let bytes = to_canonical_json(&release).expect("canonical release");
        assert_eq!(
            ContainerRelease::from_json(&bytes).expect("strict release"),
            release
        );
    }

    #[test]
    fn signature_input_binds_every_unsigned_final_release_field() {
        let release = release_fixture();
        let input = signature_input_fixture();
        let bytes = to_canonical_json(&input).expect("canonical signature input");

        assert_eq!(
            ContainerSignatureInput::from_canonical_json(&bytes).expect("strict signature input"),
            input
        );
        input
            .validate_final_release(&release)
            .expect("exact final release binding");

        let mut mismatched = release;
        mismatched.identity.package_version = "0.1.1".to_string();
        assert!(input.validate_final_release(&mismatched).is_err());
    }

    #[test]
    fn strict_dsse_envelope_preserves_exact_canonical_input_and_pae() {
        let input = signature_input_fixture();
        let payload = to_canonical_json(&input).expect("canonical signature input");
        let envelope = ContainerDsseEnvelope {
            payload_type: CONTAINER_SIGNATURE_INPUT_MEDIA_TYPE.to_string(),
            payload: base64::engine::general_purpose::STANDARD.encode(&payload),
            signatures: vec![ContainerDsseSignature {
                keyid: base64::engine::general_purpose::STANDARD.encode(b"ssh-key"),
                sig: base64::engine::general_purpose::STANDARD.encode(b"armored signature"),
            }],
        };
        let bytes = to_canonical_json(&envelope).expect("canonical DSSE envelope");
        let parsed = ContainerDsseEnvelope::from_json(&bytes).expect("strict DSSE envelope");
        assert_eq!(
            parsed.signature_input().expect("signature input").0,
            payload
        );

        let mut expected = format!(
            "DSSEv1 {} {} {} ",
            CONTAINER_SIGNATURE_INPUT_MEDIA_TYPE.len(),
            CONTAINER_SIGNATURE_INPUT_MEDIA_TYPE,
            payload.len()
        )
        .into_bytes();
        expected.extend_from_slice(&payload);
        assert_eq!(parsed.pae().expect("DSSE PAE"), expected);
    }

    #[test]
    fn strict_dsse_envelope_rejects_ambiguous_or_noncanonical_encoding() {
        let input = signature_input_fixture();
        let payload = to_canonical_json(&input).expect("canonical signature input");
        let signature = ContainerDsseSignature {
            keyid: base64::engine::general_purpose::STANDARD.encode(b"ssh-key"),
            sig: base64::engine::general_purpose::STANDARD.encode(b"armored signature"),
        };
        let mut envelope = ContainerDsseEnvelope {
            payload_type: CONTAINER_SIGNATURE_INPUT_MEDIA_TYPE.to_string(),
            payload: base64::engine::general_purpose::STANDARD.encode(payload),
            signatures: vec![signature.clone()],
        };

        envelope.signatures.push(signature);
        assert!(envelope.validate().is_err());
        envelope.signatures.truncate(1);
        envelope.payload_type = "application/vnd.in-toto+json".to_string();
        assert!(envelope.validate().is_err());
        envelope.payload_type = CONTAINER_SIGNATURE_INPUT_MEDIA_TYPE.to_string();
        envelope.payload.push('\n');
        assert!(envelope.validate().is_err());
    }

    #[test]
    fn canonical_parsers_reject_semantically_equivalent_pretty_json() {
        let release = release_fixture();
        let bytes = serde_json::to_vec_pretty(&release).expect("pretty release");
        assert!(ContainerRelease::from_json(&bytes).is_ok());
        assert!(ContainerRelease::from_canonical_json(&bytes).is_err());

        let input = signature_input_fixture();
        let bytes = serde_json::to_vec_pretty(&input).expect("pretty input");
        assert!(ContainerSignatureInput::from_json(&bytes).is_ok());
        assert!(ContainerSignatureInput::from_canonical_json(&bytes).is_err());
    }

    #[test]
    fn rejects_unknown_fields_at_every_signed_schema_boundary() {
        let release = release_fixture();
        let mut value = serde_json::to_value(&release).expect("release JSON");
        value
            .as_object_mut()
            .expect("release object")
            .insert("future".to_string(), serde_json::json!(true));
        let bytes = serde_json::to_vec(&value).expect("release bytes");
        assert!(matches!(
            ContainerRelease::from_json(&bytes),
            Err(Error::Json {
                document: "AOS container release",
                ..
            })
        ));

        let mut value = serde_json::to_value(release_fixture()).expect("release JSON");
        value["oci"]["platformManifests"][0]["platform"]["future"] = serde_json::json!(true);
        let bytes = serde_json::to_vec(&value).expect("release bytes");
        assert!(ContainerRelease::from_json(&bytes).is_err());

        let mut value = serde_json::to_value(release_fixture()).expect("release JSON");
        value["evidence"]["sbom"]["future"] = serde_json::json!(true);
        let bytes = serde_json::to_vec(&value).expect("release bytes");
        assert!(ContainerRelease::from_json(&bytes).is_err());
    }

    #[test]
    fn reports_exact_schema_identity_and_media_errors() {
        let mut release = release_fixture();
        release.schema_version = 2;
        assert_eq!(
            release.validate(),
            Err(Error::InvalidValue {
                field: "container release schemaVersion",
                reason: "expected 1, got 2".to_string(),
            })
        );

        let mut release = release_fixture();
        release.media_type = MediaType::OciImageIndex;
        assert_eq!(
            release.validate(),
            Err(Error::InvalidValue {
                field: "container release mediaType",
                reason: format!(
                    "expected {}, got {}",
                    MediaType::AosContainerRelease,
                    MediaType::OciImageIndex
                ),
            })
        );
    }

    #[test]
    fn enforces_identity_and_nix_provenance_bounds() {
        let mut release = release_fixture();
        release.identity.package = "x".repeat(MAX_CONTAINER_RELEASE_IDENTITY_BYTES + 1);
        assert_eq!(
            release.validate(),
            Err(Error::InvalidValue {
                field: "container release identity package",
                reason: format!(
                    "value is {} bytes; the limit is {MAX_CONTAINER_RELEASE_IDENTITY_BYTES}",
                    MAX_CONTAINER_RELEASE_IDENTITY_BYTES + 1
                ),
            })
        );

        let mut release = release_fixture();
        release.nix.definition.attribute = "containerImages..aos".to_string();
        assert_eq!(
            release.validate(),
            Err(Error::InvalidValue {
                field: "container release Nix definition attribute",
                reason: "value must be dot-separated non-empty ASCII attribute segments"
                    .to_string(),
            })
        );

        let mut release = release_fixture();
        release.nix.output.store_path = "/tmp/not-a-store-output".to_string();
        assert_eq!(
            release.validate(),
            Err(Error::InvalidValue {
                field: "container release Nix output storePath",
                reason: "value must be below /nix/store".to_string(),
            })
        );
    }

    #[test]
    fn definition_attribute_matching_is_closed_to_one_system_variant() {
        assert!(definition_attribute_matches_image(
            "containerImages.aos",
            "aos"
        ));
        assert!(definition_attribute_matches_image(
            "systems.server.build.containers.aos",
            "aos"
        ));
        assert!(definition_attribute_matches_image(
            "systems.aos-testing.build.containers.aos",
            "aos"
        ));
        assert!(!definition_attribute_matches_image(
            "systems.server.build.containers.other",
            "aos"
        ));
        assert!(!definition_attribute_matches_image(
            "systems.nested.server.build.containers.aos",
            "aos"
        ));
    }

    #[test]
    fn requires_exact_oci_index_and_platform_manifest_roles() {
        let mut release = release_fixture();
        release.oci.index.media_type = MediaType::OciImageManifest;
        assert_eq!(
            release.validate(),
            Err(Error::InvalidValue {
                field: "container release OCI index",
                reason: format!(
                    "expected mediaType {}, got {}",
                    MediaType::OciImageIndex,
                    MediaType::OciImageManifest
                ),
            })
        );

        let mut release = release_fixture();
        release.oci.platform_manifests[0].platform = None;
        assert_eq!(
            release.validate(),
            Err(Error::InvalidValue {
                field: "container release platform manifest",
                reason: "a platform manifest descriptor must declare a platform".to_string(),
            })
        );

        let mut release = release_fixture();
        let duplicate = release.oci.platform_manifests[0].clone();
        release.oci.platform_manifests.push(duplicate);
        assert_eq!(
            release.validate(),
            Err(Error::InvalidValue {
                field: "container release platformManifests",
                reason: format!(
                    "manifest digest {} is duplicated",
                    release.oci.platform_manifests[0].digest
                ),
            })
        );

        let mut release = release_fixture();
        let mut duplicate_platform = release.oci.platform_manifests[0].clone();
        duplicate_platform.digest = Sha256Digest::digest(b"second-manifest");
        release.oci.platform_manifests.push(duplicate_platform);
        assert_eq!(
            release.validate(),
            Err(Error::InvalidValue {
                field: "container release platformManifests",
                reason: "platform linux/amd64 is duplicated".to_string(),
            })
        );
    }

    #[test]
    fn requires_every_evidence_referrer_media_role() {
        let mut release = release_fixture();
        release.evidence.sbom.artifact_type = Some(MediaType::AosLicenseReport);
        assert_eq!(
            release.validate(),
            Err(Error::InvalidValue {
                field: "container release SBOM",
                reason: format!(
                    "expected artifactType {}, got {}",
                    MediaType::SpdxJson,
                    MediaType::AosLicenseReport
                ),
            })
        );

        let mut release = release_fixture();
        release.nix.closure.media_type = MediaType::AosNixClosure;
        assert_eq!(
            release.validate(),
            Err(Error::InvalidValue {
                field: "container release closure",
                reason: format!(
                    "evidence referrer must use mediaType {}, got {}",
                    MediaType::OciImageManifest,
                    MediaType::AosNixClosure
                ),
            })
        );
    }

    #[test]
    fn bounds_platform_collections_and_json_descriptor_sizes() {
        let mut release = release_fixture();
        release.oci.platform_manifests.clear();
        assert_eq!(
            release.validate(),
            Err(Error::InvalidValue {
                field: "container release platformManifests",
                reason: "at least one platform manifest is required".to_string(),
            })
        );

        let mut release = release_fixture();
        let template = release.oci.platform_manifests[0].clone();
        release.oci.platform_manifests = (0..=MAX_PLATFORMS_PER_INDEX)
            .map(|index| Descriptor {
                digest: Sha256Digest::digest(index.to_string().as_bytes()),
                ..template.clone()
            })
            .collect();
        assert_eq!(
            release.validate(),
            Err(Error::TooManyItems {
                field: "container release platformManifests",
                limit: MAX_PLATFORMS_PER_INDEX,
                actual: MAX_PLATFORMS_PER_INDEX + 1,
            })
        );

        let mut release = release_fixture();
        release.oci.index.size = u64::try_from(MAX_JSON_BYTES + 1).expect("fixture size");
        assert_eq!(
            release.validate(),
            Err(Error::InvalidValue {
                field: "container release OCI index",
                reason: format!(
                    "descriptor size {} exceeds the {MAX_JSON_BYTES}-byte JSON limit",
                    MAX_JSON_BYTES + 1
                ),
            })
        );
    }
}
