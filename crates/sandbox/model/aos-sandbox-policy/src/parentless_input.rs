//! Materializes the existing parentless inherited input from authenticated layers.
//!
//! These constructors preserve the sole compiler model recipe. Their inputs
//! retain existing authenticated model brands; they do not issue native
//! publication, currentness, effects or a receiving original.

use crate::signed_inputs::PolicyDeploymentSourcesV1;
use crate::{
    AuthenticatedSandboxProjectRelationV1, CacheDomainInputV1, HardLimitRequestV1,
    HardLimitValueV1, HardResourceKeyV1, HardResourceProfileV1, PORTABLE_LIMIT_DIMENSIONS,
    PolicyCompilerInputV1, PolicyCompilerLimitsV1, PolicyLayerV1, ProjectPolicyInputV1,
    RequestPolicyInputV1, RevocationInputV1,
};
use aos_sandbox_model::{ObjectDigest, ResourceDimension};
use sha2::{Digest as _, Sha256};

/// Preserves the existing model and inherited-resource construction errors.
#[derive(Debug, thiserror::Error)]
pub enum ParentlessPolicyInputDataErrorV1 {
    /// Retains the sole authenticated model constructor failure.
    #[error(transparent)]
    Model(#[from] crate::PolicyModelError),
    /// Retains the complete inherited hard-resource profile failure.
    #[error(transparent)]
    Resources(#[from] crate::HardResourceModelError),
}

/// Constructs the inherited parentless input from already authenticated model layers.
///
/// # Errors
///
/// Retains rejected project, request, inherited-resource and compiler model causes.
pub fn parentless_create_input_from_authenticated_layers_v1(
    relation: AuthenticatedSandboxProjectRelationV1,
    project_layer: PolicyLayerV1,
    deployment: &PolicyDeploymentSourcesV1,
) -> Result<PolicyCompilerInputV1, ParentlessPolicyInputDataErrorV1> {
    let project = ProjectPolicyInputV1::new(relation.project(), project_layer)?;
    let request = RequestPolicyInputV1::new(inherited_request_layer()?)?;
    Ok(PolicyCompilerInputV1::new(
        relation,
        deployment.node().clone(),
        deployment.site().clone(),
        project,
        Vec::new(),
        request,
        deployment.endpoints().clone(),
        deployment.destinations().clone(),
        deployment.backend().clone(),
        PolicyCompilerLimitsV1::DEFAULT,
    )?)
}

/// Constructs a request layer that inherits every portable and accounting limit.
///
/// # Errors
///
/// Retains invalid resource requests, profiles or layer construction causes.
pub fn inherited_request_layer() -> Result<PolicyLayerV1, ParentlessPolicyInputDataErrorV1> {
    let portable = PORTABLE_LIMIT_DIMENSIONS
        .into_iter()
        .map(|dimension| {
            HardLimitRequestV1::new(
                HardResourceKeyV1::Portable(dimension),
                HardLimitValueV1::Inherit,
                None,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let accounting = ResourceDimension::ALL
        .into_iter()
        .map(|dimension| {
            HardLimitRequestV1::new(
                HardResourceKeyV1::Accounting(dimension),
                HardLimitValueV1::Inherit,
                None,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(PolicyLayerV1::new(
        Vec::new(),
        HardResourceProfileV1::new(portable, accounting)?,
        Vec::new(),
        Vec::new(),
        CacheDomainInputV1::Inherit,
        RevocationInputV1::Inherit,
    )?)
}


/// Commits the five canonical parentless explicit-draft comparison digests.
#[must_use]
pub fn parentless_explicit_draft_digest_v2(
    source: ObjectDigest,
    project_packet: ObjectDigest,
    project_input: ObjectDigest,
    prerequisites: ObjectDigest,
    normalized_input: ObjectDigest,
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.public-create-policy-draft.v2\0")
            .chain_update(source.as_bytes())
            .chain_update(project_packet.as_bytes())
            .chain_update(project_input.as_bytes())
            .chain_update(prerequisites.as_bytes())
            .chain_update(normalized_input.as_bytes())
            .finalize()
            .into(),
    )
}

/// Describes the existing bounded parentless compiler materialization DATA.
///
/// The model/cell recipe supplies no payer or admission. Both the original
/// Controller capture and native Policy compiler separately debit their own
/// genuine receiving original before model construction.
pub struct CompilerMaterializationShapeDataV1 {
    /// Bounds the retained provenance record bytes used by the existing recipe.
    pub origin_bytes: usize,
    /// Bounds one owned decoded/compiler cell and its canonical byte controls.
    pub cell_bytes: usize,
    /// Bounds owned compiler cells by their admitted original representation.
    pub compiler_cells: usize,
    /// Bounds the complete existing input/output/model memory representation.
    pub compiler_memory: usize,
}

/// Derives the sole existing parentless compiler materialization bound.
///
/// # Errors
///
/// Returns `None` on checked representation overflow.
#[must_use]
pub fn compiler_materialization_shape_v1() -> Option<CompilerMaterializationShapeDataV1> {
    let layer = crate::MAXIMUM_POLICY_LAYER_BYTES;
    let input_bytes = layer.checked_mul(4 + 2 + 1)?;
    let output_bytes = layer.checked_mul(4)?;
    let origin_bytes = 4_usize.checked_mul(1024)?.checked_mul(1024)?;
    let compiler_bytes = input_bytes
        .checked_add(output_bytes)?
        .checked_mul(2)?
        .checked_add(origin_bytes.checked_mul(2)?)?;
    let cell_bytes = std::mem::size_of::<(Vec<u8>, Vec<u8>, [usize; 4])>()
        .checked_add(std::mem::size_of::<crate::PolicyLayerV1>())?
        .checked_add(std::mem::size_of::<crate::CompiledPolicyCandidateV1>())?
        .checked_add(std::mem::size_of::<crate::PolicyCompilerInputV1>())?;
    let compiler_cells = compiler_bytes;
    let compiler_memory = compiler_bytes
        .checked_add(compiler_cells.checked_mul(cell_bytes)?)?
        .checked_add(std::mem::size_of::<crate::PolicyCompilerInputV1>())?
        .checked_add(std::mem::size_of::<crate::CompiledPolicyCandidateV1>())?;
    Some(CompilerMaterializationShapeDataV1 {
        origin_bytes,
        cell_bytes,
        compiler_cells,
        compiler_memory,
    })
}

/// Prices the finite forwarding controls introduced by the shared constructors.
///
/// Input and layer backing remain in the original materialization recipe. The
/// returned demand covers lower typed results and the shape transfer interfaces;
/// it conveys no receiving original or admission.
#[must_use]
pub fn additional_construction_control_bytes_v1() -> Option<usize> {
    [
        std::mem::size_of::<Result<PolicyCompilerInputV1, ParentlessPolicyInputDataErrorV1>>(),
        std::mem::size_of::<Result<PolicyLayerV1, ParentlessPolicyInputDataErrorV1>>(),
        std::mem::size_of::<Option<CompilerMaterializationShapeDataV1>>(),
        std::mem::size_of::<Option<usize>>(),
    ]
    .into_iter()
    .try_fold(0_usize, |sum, bytes| sum.checked_add(bytes))
    .and_then(|bytes| bytes.checked_mul(2))
}
