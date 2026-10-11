//! Implementation-keyed candidate verification beneath original vendor custody.

use super::{VendorCnpNode, refused, unknown};
use crate::{
    node_contract::{
        InstalledNativeCapture, NativeCaptureArtifact, NativeCaptureLimits, NativeStateKey,
        OperationFailure, RuntimeSnapshot, SavedRuntimeActivation, WorldActivation,
    },
    node_scheduling::InputPayload,
};
use crucible_node_contract::{Id, Position, Validate};

/// Owns unqualified candidate records and artifacts from a stopped original.
///
/// Public construction grants no capture seal. The installed source inspector
/// and adapter independently check exact implementation/profile/schema identity,
/// the actual complete runtime cut and bounded full content before sealing.
pub struct VendorNativeCapture {
    /// Names the actual capture owner of every participant.
    pub owner: Id,
    /// Names the complete capture group in canonical node order.
    pub participants: Vec<Id>,
    /// Selects exact implementation/profile/state-schema compatibility.
    pub key: NativeStateKey,
    /// Retains the original authentic coordinator cut.
    pub cut: Position,
    /// Contains the complete state body under its full content identity.
    pub state: InputPayload,
    /// Retains all original semantic proof and reconstruction bodies.
    pub evidence: Vec<InputPayload>,
    /// Owns complete opened native artifacts rather than guessed paths.
    pub artifacts: Vec<NativeCaptureArtifact>,
}

impl VendorCnpNode {
    pub(super) fn capture_original(
        &mut self,
        activation: &WorldActivation,
        runtime: &RuntimeSnapshot,
        limits: NativeCaptureLimits,
    ) -> Result<InstalledNativeCapture, OperationFailure> {
        let state = self.state_mut()?;
        state.current()?;
        if state.uncertain
            || state.quarantined
            || state.capture.is_some()
            || state
                .active
                .as_ref()
                .is_none_or(|active| !active.same_authority(activation))
            || runtime.source_activation != SavedRuntimeActivation::from(activation.record())
        {
            return Err(refused(
                "vendor capture is not the unchanged active original runtime",
            ));
        }
        let identity = state
            .identity
            .as_ref()
            .ok_or_else(|| refused("vendor identity absent"))?;
        let codec = state
            .codec
            .as_ref()
            .ok_or_else(|| refused("vendor capture codec absent"))?;
        state.uncertain = true;
        let candidate = match codec.capture(identity, &mut state.peer, activation, runtime, limits)
        {
            Ok(candidate) => candidate,
            Err(error) => {
                if error.effects == crate::node_contract::EffectKnowledge::None {
                    state.uncertain = false;
                }
                return Err(error);
            }
        };
        // Keep all returned originals before any validator or artifact read.
        state.capture = Some(candidate);
        let candidate = state
            .capture
            .as_ref()
            .ok_or_else(|| unknown("original capture custody disappeared"))?;
        let binding = &identity.binding.compatibility;
        if candidate.owner != binding.capture_owner.id
            || candidate.participants != binding.capture_owner.participant_ids
            || candidate.key.implementation != binding.implementation.implementation_id
            || candidate.key.profile != identity.profile
            || !binding
                .implementation
                .formats
                .contains(&candidate.key.schema)
            || candidate.cut != runtime.capture_cut
        {
            return Err(unknown(
                "vendor capture changed original key/participants/cut",
            ));
        }
        candidate
            .key
            .schema
            .validate()
            .map_err(|error| unknown(&error.to_string()))?;
        let mut bytes = 0usize;
        let mut objects = 0usize;
        for object in std::iter::once(&candidate.state).chain(&candidate.evidence) {
            bytes = bytes
                .checked_add(object.bytes.len())
                .filter(|bytes| *bytes <= limits.maximum_total_record_bytes)
                .ok_or_else(|| unknown("vendor capture record aggregate credit exhausted"))?;
            objects = objects
                .checked_add(1)
                .filter(|objects| *objects <= limits.maximum_objects)
                .ok_or_else(|| unknown("vendor capture object count credit exhausted"))?;
            if object.bytes.len() > limits.maximum_record_bytes {
                return Err(unknown("vendor capture record extent exceeds credit"));
            }
            object
                .reference
                .verify(&object.bytes)
                .map_err(|error| unknown(&error.to_string()))?;
        }
        let mut artifact_bytes = 0u64;
        if candidate.artifacts.len() > limits.maximum_objects {
            return Err(unknown("vendor capture artifact count credit exhausted"));
        }
        for artifact in &candidate.artifacts {
            artifact_bytes = artifact_bytes
                .checked_add(artifact.reference().length.get())
                .filter(|bytes| *bytes <= limits.maximum_total_artifact_bytes)
                .ok_or_else(|| unknown("vendor capture artifact aggregate credit exhausted"))?;
            if artifact.reference().length.get() > limits.maximum_artifact_bytes {
                return Err(unknown("vendor capture artifact extent exceeds credit"));
            }
            artifact.verify().map_err(|error| unknown(&error.reason))?;
        }
        codec
            .validate_capture(identity, &state.peer, activation, runtime, candidate)
            .map_err(|error| unknown(&error.reason))?;
        state.current()?;
        let candidate = state
            .capture
            .take()
            .ok_or_else(|| unknown("vendor original capture disappeared"))?;
        state.uncertain = false;
        Ok(InstalledNativeCapture {
            owner: candidate.owner,
            participants: candidate.participants,
            key: candidate.key,
            cut: candidate.cut,
            state: candidate.state,
            evidence: candidate.evidence,
            artifacts: candidate.artifacts,
        })
    }
}
