//! Materializes a selected immutable Environment deployment instruction.
//!
//! The administrative instruction wraps the existing canonical generation
//! codec. It is DATA until the actual Root owner joins its fixed native input,
//! measured profile, current deployment and accepted subject. Only the sandbox
//! identity is rebound; all semantic content must match the fresh Root inputs.
//!
//! ```text
//! AOSENVT1 | version:u16be=1 | reserved:6 | canonical-generation-manifest
//! ```

mod native;
mod accepted;
pub(crate) mod transport;
mod response;
mod provisional;
mod publication;
pub(crate) use provisional::RootEnvironmentProvisionalDataV1;
pub(crate) use publication::{PreparedEnvironmentPublicationV1, EnvironmentSourcePublicationOriginalV1};
pub(crate) use response::RootEnvironmentResponseOriginalV1;
pub(crate) use accepted::RootEnvironmentAcceptedOriginalV1;
pub(crate) use native::{RootEnvironmentDeploymentOriginalV1, EnvironmentDeploymentErrorV1};

use aos_sandbox_model::{ObjectDescriptor, ProjectId, SandboxId};
use aos_sandbox_model::model::CacheDomain;

use super::{
    EnvironmentGenerationManifestV1, EnvironmentModelError,
    decode_environment_generation_v1, encode_environment_generation_v1,
};

const MAGIC: &[u8; 8] = b"AOSENVT1";
const VERSION: u16 = 1;
const PREFIX_BYTES: usize = 16;

/// Keeps the canonical DATA selected by Root's actual immutable installation.
///
/// A template cannot mint a generation publication, GC acknowledgement,
/// current Environment source, execution lease or effect capability.
pub(crate) struct EnvironmentDeploymentTemplateV1 {
    generation: EnvironmentGenerationManifestV1,
}

impl EnvironmentDeploymentTemplateV1 {
    pub(crate) fn decode(encoded: &[u8]) -> Result<Self, EnvironmentModelError> {
        let body = encoded.get(PREFIX_BYTES..).ok_or(EnvironmentModelError::CorruptEncoding)?;
        if encoded.get(..8) != Some(MAGIC.as_slice())
            || encoded.get(8..10) != Some(VERSION.to_be_bytes().as_slice())
            || encoded.get(10..PREFIX_BYTES) != Some([0; 6].as_slice())
        {
            return Err(EnvironmentModelError::CorruptEncoding);
        }
        let generation = decode_environment_generation_v1(body)?;
        if generation.generation().get() != 1
            || generation.predecessor().is_some()
            || encode_environment_generation_v1(&generation)? != body
        {
            return Err(EnvironmentModelError::InvalidModel);
        }
        Ok(Self { generation })
    }

    /// Constructs the ordinary canonical first generation for the real subject.
    ///
    /// The actual Root compiler supplies these comparisons from its fresh
    /// protected cut. No caller-provided identities authorize publication.
    pub(crate) fn materialize_v1(
        &self,
        project: ProjectId,
        sandbox: SandboxId,
        environment: &ObjectDescriptor,
        root_view: &ObjectDescriptor,
        effective_policy: &ObjectDescriptor,
        disclosure: CacheDomain,
    ) -> Result<EnvironmentGenerationManifestV1, EnvironmentModelError> {
        let generation = &self.generation;
        if generation.project() != project
            || generation.environment_descriptor() != environment
            || generation.facade().descriptor() != root_view
            || generation.effective_policy() != effective_policy
            || generation.disclosure() != disclosure
        {
            return Err(EnvironmentModelError::InvalidModel);
        }
        EnvironmentGenerationManifestV1::new(
            project,
            sandbox,
            generation.generation(),
            None,
            generation.environment().clone(),
            generation.environment_descriptor().clone(),
            generation.selected_output().clone(),
            generation.target_system().clone(),
            generation.facade().clone(),
            generation.effective_policy().clone(),
            generation.disclosure().clone(),
            generation.inputs().to_vec(),
        )
    }

    pub(crate) fn template_v1(&self) -> &EnvironmentGenerationManifestV1 {
        &self.generation
    }
}
