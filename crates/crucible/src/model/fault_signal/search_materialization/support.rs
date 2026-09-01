//! Artifact persistence, identity material, and materialization errors.

use super::*;

pub(super) fn put_verified(
    store: &dyn DagStore,
    bytes: &[u8],
    expected: ContentHash,
) -> Result<(), SearchMaterializationError> {
    let actual = store
        .put(bytes)
        .map_err(SearchMaterializationError::Store)?;
    if actual == expected {
        Ok(())
    } else {
        Err(SearchMaterializationError::ContentMismatch)
    }
}

pub(super) fn get_verified(
    store: &dyn DagStore,
    expected: ContentHash,
) -> Result<Vec<u8>, SearchMaterializationError> {
    let bytes = store
        .get(&expected)
        .map_err(SearchMaterializationError::Store)?;
    if ContentHash::from_bytes(&bytes) == expected {
        Ok(bytes)
    } else {
        Err(SearchMaterializationError::ContentMismatch)
    }
}

pub(super) fn trace_mutation_material(
    program: ContentHash,
    binding: &FaultObjectId,
    artifact: ContentHash,
    mutation: &TraceWindowMaterialization,
) -> Result<String, SearchMaterializationError> {
    let mut material = format!(
        "program={};binding={};artifact={};node={};samples=",
        program.to_hex(),
        binding.as_str(),
        artifact.to_hex(),
        mutation.trace_node.as_str(),
    );
    for sample in &mutation.samples {
        material.push_str(&format!(
            "{}:{:?}:{};",
            sample.coordinate,
            sample.event_sequence,
            hex_bytes(
                &super::trace::encode_signal_value(&sample.value)
                    .map_err(SearchMaterializationError::Trace)?
            ),
        ));
    }
    Ok(material)
}

pub(super) fn mapping_mutation_material(
    program: ContentHash,
    binding: &FaultObjectId,
    mutation: &MappingMaterialization,
) -> Result<String, SearchMaterializationError> {
    let mut material = format!(
        "program={};binding={};points=",
        program.to_hex(),
        binding.as_str(),
    );
    for replacement in &mutation.points {
        material.push_str(&format!(
            "{}:{}:{};",
            replacement.index,
            hex_bytes(
                &super::trace::encode_signal_value(&replacement.point.input)
                    .map_err(SearchMaterializationError::Trace)?
            ),
            hex_bytes(
                &super::trace::encode_signal_value(&replacement.point.output)
                    .map_err(SearchMaterializationError::Trace)?
            ),
        ));
    }
    Ok(material)
}

pub(super) fn materialization_digest(
    original_program: ContentHash,
    binding: &FaultBinding,
    materialized_program: ContentHash,
    mutation_material: &str,
) -> Result<ContentHash, SearchMaterializationError> {
    let binding_contract = binding
        .contract_digest()
        .map_err(SearchMaterializationError::BindingCodec)?;
    Ok(ContentHash::from_canonical_material(
        "crucible.materialized-binding-search.v1",
        &format!(
            "signal_evaluator_version={};effect_semantic_version={};search_materializer_version=1;original_program={};materialized_program={};binding_contract={};mutation={mutation_material}",
            SIGNAL_EVALUATOR_VERSION,
            EFFECT_SEMANTIC_VERSION,
            original_program.to_hex(),
            materialized_program.to_hex(),
            binding_contract.to_hex(),
        ),
    ))
}

pub(super) fn hex_bytes(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[usize::from(byte >> 4)] as char);
        output.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    output
}

/// Failure to turn a bounded mutation policy into ordinary fixed inputs.
#[derive(Debug)]
pub enum SearchMaterializationError {
    /// Binding uses a different search policy or mapping.
    WrongPolicy,
    /// Binding was admitted against a different original signal program.
    ProgramIdentity,
    /// Trace node is not an exact authorized input of this binding.
    UnauthorizedTraceNode,
    /// Mutation count, identity, order, or authored window is invalid.
    InvalidMutation,
    /// Cartesian candidate materialization exceeds the scenario search bound.
    CandidateProductLimit,
    /// Named signal node is absent or is not a normalized trace source.
    UnknownTraceNode,
    /// Trace manifest omits the source node's selected channel.
    UnknownTraceChannel,
    /// Replacement value contradicts the selected channel shape.
    MutationType,
    /// Mutation coordinate does not identify an existing source sample.
    MissingSample,
    /// Loaded manifest referenced no corresponding decoded chunk.
    MissingChunk,
    /// Store returned an identity other than the canonical object digest.
    ContentMismatch,
    /// Signal program or identifier validation failed.
    Program(SignalProgramError),
    /// Virtual-time projection of a stored trace coordinate failed.
    Evaluation(SignalEvaluationError),
    /// Closed fault identifier validation failed.
    Contract(FaultContractError),
    /// Concrete fixed binding failed admission.
    Binding(BindingError),
    /// Reconstructed complete fault plan failed admission.
    Plan(FaultSignalPlanError),
    /// Canonical binding-contract encoding failed.
    BindingCodec(serde_json::Error),
    /// Canonical trace codec validation failed.
    Trace(TraceError),
    /// Trace dependency loading failed.
    TraceStore(TraceArtifactStoreError),
    /// Content-addressed persistence failed.
    Store(DagStoreError),
}

impl fmt::Display for SearchMaterializationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "fault search materialization failed: {self:?}")
    }
}

impl Error for SearchMaterializationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Program(error) => Some(error),
            Self::Evaluation(error) => Some(error),
            Self::Contract(error) => Some(error),
            Self::Binding(error) => Some(error),
            Self::Plan(error) => Some(error),
            Self::BindingCodec(error) => Some(error),
            Self::Trace(error) => Some(error),
            Self::TraceStore(error) => Some(error),
            Self::Store(error) => Some(error),
            _ => None,
        }
    }
}
