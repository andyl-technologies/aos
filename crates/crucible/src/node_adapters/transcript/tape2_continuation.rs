//! Authenticates reference-only Tape2 journals beneath coordinator7.
//!
//! ```text
//! {"schema_version":2,"runtime":{},"route":{},"binding":{},"cursor":{},
//!  "boundary":{},"transcript":{},"qualification":{},
//!  "operation_evidence":[],"observations":[],"custody_objects":[]}
//! ```
//!
//! FIRST tape scopes, SOURCE-CAPTURE Runtime7 and future TARGET preparation are
//! distinct. This reader authenticates historical journals only; it neither
//! installs runtime permissions nor qualifies a physical backend for capture.

use std::{collections::BTreeSet, rc::Rc};

use crucible_node_contract::{
    ContentRef, Id, NodeBinding, Position, SchemaRef, Validate, canonical,
};
use serde::{Deserialize, Serialize};

use crate::{
    node_contract::{
        ActivationRecord, EffectKnowledge, NativeRuntimeContinuationVerifier, NodeRoute,
        NodeRuntime, OperationFailure, OriginalLineageRestoration,
        OriginalLineageRestorationLimits, RuntimeError,
    },
    node_scheduling::NativeSchedulingObservation,
    node_state::AuthenticatedOriginalLineageSource,
};

use super::{
    AuthenticatedTranscript, BoundaryTranscript, ReplayCursorSnapshot,
    codec::invalid,
    control::failure,
    node::continuation::{bounded_canonical, validate_preservation_trajectory},
};

#[path = "tape2_continuation_prefix.rs"]
mod prefix;

/// Identifies complete conditional Tape2 model journals, separate from v1 replay.
pub const TRANSCRIPT_ORIGINAL_LINEAGE_CONTINUATION_PROFILE: &str =
    "transcript/complete-original-lineage-continuation-v2";

const SPECIFICATION: &str = "crucible/transcript-original-lineage-continuation-v2: reference-only complete Runtime7 below authenticated coordinator7 and TypedIndex2; exact original source transcript/context and consumed cutoff, separate FIRST input/publication ancestry and SOURCE-CAPTURE activation, sticky cursor, complete original pending operation permissions, held outcomes/input acknowledgements, raw per-role proof and administrative custody chains. Actual installed producer and consumer journal verification and fresh TARGET qualification/publication are mandatory before installing authority. No physical-source preservation, arbitrary DTO authority, future-prefix evidence release, owner relabeling or implicit combined alarm/fault/terminal/selected-extension scope. Unsupported original negative and uncertain trajectories refuse independently of installed policy.";
const MAXIMUM_RECORD_BYTES: usize = 64 * 1024 * 1024;
const MAXIMUM_OBJECTS: usize = 8192;

/// Returns immutable installed Tape2 continuation specification bytes.
pub fn original_lineage_continuation_definition() -> &'static [u8] {
    SPECIFICATION.as_bytes()
}

/// Returns the separately selected complete Tape2 model codec identity.
///
/// # Errors
/// Returns portable identity or immutable definition construction errors.
pub fn original_lineage_continuation_schema() -> Result<SchemaRef, OperationFailure> {
    Ok(SchemaRef {
        id: Id::new("transcript/original-lineage-continuation-v2")
            .map_err(|error| failure(error, EffectKnowledge::None))?,
        version: 2,
        definition: canonical::content_ref(SPECIFICATION.as_bytes(), "text/plain")
            .map_err(|error| failure(error, EffectKnowledge::None))?,
        extensions: Default::default(),
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OperationEvidence {
    pub operation: Id,
    pub objects: Vec<ContentRef>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Tape2ContinuationWire {
    #[serde(deserialize_with = "crucible_node_contract::deserialize_version")]
    pub schema_version: u16,
    pub runtime: ContentRef,
    pub route: NodeRoute,
    pub binding: NodeBinding,
    pub cursor: ReplayCursorSnapshot,
    pub boundary: Position,
    pub transcript: ContentRef,
    pub qualification: ContentRef,
    pub operation_evidence: Vec<OperationEvidence>,
    pub observations: Vec<NativeSchedulingObservation>,
    pub custody_objects: Vec<ContentRef>,
}

/// Borrows historical Tape2 journals authenticated by the complete signed source.
///
/// Neither this seal nor its DTO accessors can mint current native authority.
/// A selected installed restoration path must independently validate actual
/// producer/consumer journals against a freshly prepared whole target world.
pub struct AuthenticatedTape2Continuation<'a> {
    source: &'a AuthenticatedOriginalLineageSource<'a>,
    pub(super) wire: Tape2ContinuationWire,
    pub(super) transcript: AuthenticatedTranscript,
}

impl AuthenticatedTape2Continuation<'_> {
    /// Borrows complete SOURCE-CAPTURE Runtime7 without dropping original lineage.
    pub fn source(&self) -> &AuthenticatedOriginalLineageSource<'_> {
        self.source
    }

    /// Borrows the source-capture route, distinct from FIRST and future TARGET.
    pub fn route(&self) -> &NodeRoute {
        &self.wire.route
    }

    /// Borrows the exact signed consumed cutoff and sticky divergence state.
    pub fn cursor(&self) -> &ReplayCursorSnapshot {
        &self.wire.cursor
    }

    /// Borrows original authenticated tape/context, without releasing future data.
    pub fn transcript(&self) -> &AuthenticatedTranscript {
        &self.transcript
    }

    /// Borrows the original source-capture native model boundary.
    pub fn boundary(&self) -> Position {
        self.wire.boundary
    }

    /// Checks genuine inactive target custody through both native endpoint hooks.
    ///
    /// This connects the authenticated signed source to the selected Runtime7
    /// context gate. It does not install lineage, activate a world, or substitute
    /// parsed tape metadata for producer/consumer journal validation.
    ///
    /// # Errors
    /// Refuses foreign complete worlds/cuts, absent source bodies, unsupported
    /// installed verifier policy or either actual node's native journals.
    pub fn prepare_target_context(
        &self,
        runtime: &NodeRuntime,
        target: &ActivationRecord,
        verifier: &mut dyn NativeRuntimeContinuationVerifier,
        limits: OriginalLineageRestorationLimits,
    ) -> Result<OriginalLineageRestoration<'_>, RuntimeError> {
        if target.world_binding_hash != self.source.runtime().source_activation.world_binding_hash
            || target.boundary != self.source.runtime().capture_cut
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let context = runtime.prepare_original_lineage_restoration(
            self.source.runtime_reference(),
            self.source.content(),
            self.source.scheduling(),
            target,
            verifier,
            limits,
        )?;
        if context.record() != self.source.runtime() {
            return Err(RuntimeError::InvalidReceipt);
        }
        context.validate_current(runtime)?;
        Ok(context)
    }

    /// Borrows source applicability evidence, which does not qualify a target.
    ///
    /// # Errors
    /// Refuses an absent original role; it never substitutes empty evidence.
    pub fn original_qualification(&self) -> Result<(&ContentRef, &[u8]), OperationFailure> {
        let bytes = self
            .source
            .content()
            .get(&self.wire.qualification)
            .ok_or_else(|| refused("original Tape2 qualification role disappeared"))?;
        Ok((&self.wire.qualification, bytes))
    }
}

/// Authenticates complete original Tape2 model journals under signed Runtime7.
///
/// Runtime7 is retained as its own typed object. It is never projected into a
/// legacy Runtime2 DTO. Complete raw reference geometry is credited before any
/// tape copy, and only consumed records may explain cache evidence or lineage.
///
/// # Errors
/// Refuses another codec/owner, changed complete runtime, absent typed objects,
/// unsupported original controls, future cursor/cache data or finite excess.
pub fn authenticate_tape2_continuation<'a>(
    source: &'a AuthenticatedOriginalLineageSource<'a>,
    node: &Id,
) -> Result<AuthenticatedTape2Continuation<'a>, OperationFailure> {
    let owner = source.owner();
    if owner.key.profile.as_str() != TRANSCRIPT_ORIGINAL_LINEAGE_CONTINUATION_PROFILE
        || owner.key.schema != original_lineage_continuation_schema()?
        || owner.participants.as_slice() != std::slice::from_ref(node)
        || !owner.artifacts.is_empty()
        || owner.evidence.len() > MAXIMUM_OBJECTS
    {
        return Err(refused("unsupported complete Tape2 continuation selection"));
    }
    let raw = source
        .native()
        .map_err(|error| refused(error.to_string()))?;
    if raw.len() > MAXIMUM_RECORD_BYTES {
        return Err(refused("Tape2 continuation metadata credit exhausted"));
    }
    let value = canonical::parse_json(raw, MAXIMUM_RECORD_BYTES)
        .map_err(|error| refused(error.to_string()))?;
    let wire: Tape2ContinuationWire =
        serde_json::from_value(value).map_err(|error| refused(error.to_string()))?;
    if bounded_canonical(&wire, MAXIMUM_RECORD_BYTES)? != raw {
        return Err(refused("Tape2 continuation body is not canonical"));
    }
    validate_header(&wire, source, node)?;
    let bytes = source
        .content()
        .get(&wire.transcript)
        .ok_or_else(|| refused("original Tape2 body absent"))?;
    // The exact object extent and aggregate evidence were charged in the header.
    let mut retained = Vec::new();
    retained
        .try_reserve_exact(bytes.len())
        .map_err(|_| refused("original Tape2 allocation credit exhausted"))?;
    retained.extend_from_slice(bytes);
    let data = BoundaryTranscript::from_canonical_bytes(&retained)
        .map_err(|error| refused(error.to_string()))?;
    let transcript = AuthenticatedTranscript {
        data: Rc::new(data),
        bytes: Rc::new(retained),
        reference: wire.transcript.clone(),
    };
    validate_preservation_trajectory(&transcript).map_err(|error| refused(error.to_string()))?;
    super::tape2::validate_selected_source(&transcript)
        .map_err(|error| refused(error.to_string()))?;
    if transcript.data.origin.repeatability
        == crucible_node_contract::Repeatability::Nondeterministic
        && source.world_repeatability() != crucible_node_contract::Repeatability::Nondeterministic
    {
        return Err(refused(
            "Tape2 source capture promotes original nondeterminism",
        ));
    }
    prefix::validate(&wire, source, &transcript)?;
    Ok(AuthenticatedTape2Continuation {
        source,
        wire,
        transcript,
    })
}

fn validate_header(
    wire: &Tape2ContinuationWire,
    source: &AuthenticatedOriginalLineageSource<'_>,
    node: &Id,
) -> Result<(), OperationFailure> {
    let runtime = source.runtime();
    let owner = source.owner();
    if wire.schema_version != 2
        || wire.runtime != *source.runtime_reference()
        || wire.route.node != *node
        || wire.route.owners.len() != 1
        || wire.route.owners[0].owner != owner.owner
        || !runtime
            .source_activation
            .owners
            .contains(&wire.route.owners[0])
        || wire.binding.compatibility.implementation.implementation_id != owner.key.implementation
        || wire.cursor.schema_version != 1
        || wire.cursor.transcript != wire.transcript
        || wire.operation_evidence.len() > MAXIMUM_OBJECTS
        || wire.observations.len() > MAXIMUM_OBJECTS
        || wire.custody_objects.len() > MAXIMUM_OBJECTS
        || wire
            .operation_evidence
            .windows(2)
            .any(|pair| pair[0].operation >= pair[1].operation)
        || wire
            .custody_objects
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        return Err(refused(
            "Tape2 source-capture route or complete cursor differs",
        ));
    }
    let mut operations = runtime
        .operations
        .iter()
        .filter(|operation| operation.route.node == *node);
    if operations.clone().count() != wire.operation_evidence.len()
        || operations
            .clone()
            .any(|operation| operation.route != wire.route)
        || operations.any(|operation| {
            !wire
                .operation_evidence
                .iter()
                .any(|entry| entry.operation == operation.operation)
        })
    {
        return Err(refused(
            "Tape2 operation evidence omits original permissions",
        ));
    }
    let references = wire
        .operation_evidence
        .iter()
        .flat_map(|entry| entry.objects.iter())
        .chain(wire.custody_objects.iter())
        .chain([&wire.runtime, &wire.transcript, &wire.qualification]);
    let mut total = 0usize;
    let mut unique = BTreeSet::new();
    for reference in references {
        reference
            .validate()
            .map_err(|error| refused(error.to_string()))?;
        let bytes = source
            .content()
            .get(reference)
            .ok_or_else(|| refused("Tape2 complete journal role absent"))?;
        reference
            .verify(bytes)
            .map_err(|error| refused(error.to_string()))?;
        total = total
            .checked_add(bytes.len())
            .filter(|total| *total <= MAXIMUM_RECORD_BYTES)
            .ok_or_else(|| refused("Tape2 aggregate journal credit exhausted"))?;
        if unique.insert(reference) && unique.len() > MAXIMUM_OBJECTS {
            return Err(refused("Tape2 journal role credit exhausted"));
        }
    }
    // Additional consumed input/lineage evidence is checked below against the
    // complete signed registry; the native owner names every admitted role.
    for reference in &owner.evidence {
        if source.content().get(reference).is_none() {
            return Err(refused("Tape2 native dependency body absent"));
        }
    }
    Ok(())
}

fn refused(reason: impl Into<String>) -> OperationFailure {
    failure(invalid(reason.into()), EffectKnowledge::None)
}

#[path = "tape2_continuation_owned.rs"]
mod owned;

pub use owned::{PinnedTape2Continuation, authenticate_pinned_tape2_continuation};
