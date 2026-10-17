//! Measured gem5 implementation discovery without inferred execution authority.

use crucible_node_contract::{
    ArtifactIdentity, CaptureScope, ContentRef, Continuation, Extensions, GuaranteeProfile, Id,
    ImplementationIdentity, ProviderManifest, Repeatability, Validate, canonical,
};
use serde_json::json;

use crate::{ProviderError, conformance::measure_executable};

use super::super::{Gem5Launch, Gem5LaunchArtifact};

/// Retains the measured implementation and its conservative discovery guarantee.
///
/// Artifact hashes identify installed bytes. Neither this catalog nor its content
/// objects authorize an execution profile, a native image, or world activation.
#[derive(Clone, Debug)]
pub struct Gem5Catalog {
    manifest: ProviderManifest,
    guarantees: GuaranteeProfile,
    guarantee_reference: ContentRef,
    guarantee_bytes: Vec<u8>,
    limitations_reference: ContentRef,
    limitations_bytes: Vec<u8>,
}

impl Gem5Catalog {
    /// Measures the complete explicitly selected native implementation artifacts.
    ///
    /// The catalog advertises an empty supported-profile roster. Private event
    /// control and opaque process-image mechanics remain available to separately
    /// authorized native callers, but do not imply a public exact profile.
    ///
    /// # Errors
    /// Rejects unreadable or changed installed artifacts, an unsupported ISA,
    /// malformed identities or content, and serialization failures.
    pub fn measure(
        provider: &Gem5LaunchArtifact,
        launch: &Gem5Launch,
    ) -> Result<Self, ProviderError> {
        if !matches!(launch.guest_isa.as_str(), "x86_64" | "aarch64") {
            return Err(ProviderError::Frame("unsupported gem5 guest ISA"));
        }

        let mut artifacts = vec![
            measured("gem5", "emulator", &launch.executable)?,
            measured("guest", "guest-image", &launch.guest)?,
            measured("model", "model-definition", &launch.model_script)?,
            measured("owner", "native-controller", &launch.owner_script)?,
            measured("provider", "provider", provider)?,
        ];
        if let Some(images) = &launch.process_images {
            artifacts.extend([
                measured("image-launcher", "image-launcher", &images.launcher)?,
                measured("image-restarter", "image-restarter", &images.restarter)?,
                measured(
                    "image-runtime",
                    "image-runtime",
                    &images.reconstruction_executable,
                )?,
                measured(
                    "resource-helper",
                    "resource-helper",
                    &images.resource_helper,
                )?,
            ]);
        }
        artifacts.sort_by(|left, right| left.id.cmp(&right.id));

        let mut models = vec![
            launch.model_script.content.clone(),
            launch.owner_script.content.clone(),
        ];
        models.sort_by(|left, right| {
            (&left.hash.domain, &left.hash.digest).cmp(&(&right.hash.domain, &right.hash.digest))
        });
        models.dedup();
        let implementation = ImplementationIdentity {
            schema_version: 1,
            implementation_id: Id::new("gem5/native-process-v1")?,
            artifacts,
            model_definitions: models,
            formats: Vec::new(),
            extensions: Extensions::new(),
        };
        implementation.validate()?;

        let limitations_bytes = canonical::canonical_json(&json!({
            "schema": "crucible.gem5.discovery-limitations.v1",
            "guest_isa": launch.guest_isa,
            "qualified_execution_profiles": [],
            "unqualified_contracts": ["input-closure", "native-event-phase-mapping",
                "publication-birth-and-custody", "complete-world-continuation"],
            "extensions": {}
        }))?;
        let limitations_reference = canonical::content_ref(&limitations_bytes, "application/json")?;
        let guarantees = GuaranteeProfile {
            schema_version: 1,
            repeatability: Repeatability::Unqualified,
            capture_scope: CaptureScope::None,
            continuation: Continuation::Unsupported,
            durable_restart: false,
            isolated_fork: false,
            conditional_replay: false,
            limitations_ref: limitations_reference.clone(),
            extensions: Extensions::new(),
        };
        guarantees.validate()?;
        let guarantee_bytes = canonical::canonical_json(
            &serde_json::to_value(&guarantees)
                .map_err(crucible_node_contract::ContractError::from)?,
        )?;
        let guarantee_reference = canonical::content_ref(&guarantee_bytes, "application/json")?;
        let manifest = ProviderManifest {
            schema_version: 1,
            provider_id: Id::new("gem5/native-provider-v1")?,
            implementation,
            protocol_versions: vec![Id::new("CNP/1")?],
            supported_profiles: Vec::new(),
            extensions_supported: Vec::new(),
            qualification_refs: Vec::new(),
            extensions: Extensions::new(),
        };
        manifest.validate()?;

        Ok(Self {
            manifest,
            guarantees,
            guarantee_reference,
            guarantee_bytes,
            limitations_reference,
            limitations_bytes,
        })
    }

    /// Returns the immutable measured provider advertisement.
    pub fn manifest(&self) -> &ProviderManifest {
        &self.manifest
    }

    /// Returns conservative discovery guarantees without native authority.
    pub fn guarantees(&self) -> &GuaranteeProfile {
        &self.guarantees
    }

    /// Returns the exact conservative guarantee content identity.
    pub fn guarantee_reference(&self) -> &ContentRef {
        &self.guarantee_reference
    }

    /// Returns complete bounded content bytes used by discovery negotiation.
    pub fn content_objects(&self) -> [(&ContentRef, &[u8]); 2] {
        [
            (&self.guarantee_reference, &self.guarantee_bytes),
            (&self.limitations_reference, &self.limitations_bytes),
        ]
    }
}

fn measured(
    id: &str,
    role: &str,
    artifact: &Gem5LaunchArtifact,
) -> Result<ArtifactIdentity, ProviderError> {
    artifact.content.validate()?;
    if measure_executable(&artifact.path)? != artifact.content {
        return Err(ProviderError::Correlation(
            "gem5 installed artifact measurement differs",
        ));
    }
    Ok(ArtifactIdentity {
        id: Id::new(id)?,
        role: Id::new(role)?,
        content: artifact.content.clone(),
        extensions: Extensions::new(),
    })
}
