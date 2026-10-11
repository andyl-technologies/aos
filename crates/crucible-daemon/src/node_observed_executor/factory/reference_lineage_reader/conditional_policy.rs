//! Qualifies one installed conditional fixture against complete signed originals.
//!
//! The original native history is inspected before this allocation exists. Each
//! callback still authenticates the complete actual target and original context;
//! a portable qualification proof cannot substitute for this installed policy.

use super::conditional_source::InspectionError;

use std::rc::Rc;

use crucible::{
    node_adapters::transcript::{
        AuthenticatedTranscript, InstalledReplayPolicy, ReplayQualification, TranscriptError,
        context_commitment,
    },
    node_admission::AdmittedGraph,
    node_contract::NodeRoute,
    node_scheduling::InputPayload,
};
use crucible_node_contract::{CaptureScope, Continuation, canonical};

use super::conditional_profile::{ConditionalProfile, encode};

pub(super) struct ConditionalPolicy {
    profile: Rc<ConditionalProfile>,
}

impl ConditionalPolicy {
    pub(super) fn install(profile: Rc<ConditionalProfile>) -> Result<Self, InspectionError> {
        let actual = crucible_node_provider::conformance::measure_executable(std::path::Path::new(
            "/proc/self/exe",
        ))
        .map_err(|error| error.to_string())?;
        if actual != profile.host
            || profile.history.publications.len() != 9
            || profile.history.inputs.len() != 4
            || profile.bindings.len() != 3
        {
            return Err(
                "conditional installation lacks its actual host or inspected triple".into(),
            );
        }
        Ok(Self { profile })
    }

    pub(super) fn qualification(
        &self,
        source: &AuthenticatedTranscript,
        target: &AdmittedGraph,
        route: &NodeRoute,
        context: &[InputPayload],
        obligation: &str,
    ) -> Result<ReplayQualification, TranscriptError> {
        let refuse = |message: String| TranscriptError::Unqualified(message);
        let original = self
            .profile
            .history
            .originals
            .get(&route.node)
            .ok_or_else(|| refuse("conditional actor has no authenticated original".into()))?;
        let binding = self
            .profile
            .bindings
            .iter()
            .find(|binding| binding.compatibility.node_id == route.node)
            .ok_or_else(|| refuse("conditional actor has no installed target binding".into()))?;
        let expected_owners = self
            .profile
            .activation
            .owners
            .iter()
            .filter(|owner| owner.owner == binding.compatibility.execution_owner.id)
            .cloned()
            .collect::<Vec<_>>();
        let actual_host = crucible_node_provider::conformance::measure_executable(
            std::path::Path::new("/proc/self/exe"),
        )
        .map_err(|error| refuse(error.to_string()))?;

        if actual_host != self.profile.host
            || source.reference() != original.reference()
            || source.bytes() != original.bytes()
            || context != original.transcript().origin.context
            || route.owners != expected_owners
            || target.world() != &self.profile.world
            || target.node_ids().count() != self.profile.bindings.len()
            || self
                .profile
                .bindings
                .iter()
                .any(|expected| target.binding(&expected.compatibility.node_id) != Some(expected))
            || self
                .profile
                .owners
                .iter()
                .any(|expected| target.owner(&expected.owner.id) != Some(expected))
        {
            return Err(refuse(
                "changed signed source, original context, installed host, complete world or target ownership"
                    .into(),
            ));
        }
        let guarantees = target
            .guarantees(&route.node)
            .ok_or_else(|| refuse("conditional guarantee body is absent".into()))?;
        if !guarantees.conditional_replay
            || guarantees.repeatability != original.transcript().origin.repeatability
            || guarantees.capture_scope != CaptureScope::CompleteModel
            || guarantees.continuation != Continuation::Exact
            || !guarantees.durable_restart
            || guarantees.isolated_fork
        {
            return Err(refuse(
                "conditional model semantics or original nondeterminism differ".into(),
            ));
        }

        let binding_bytes = encode(binding).map_err(|error| refuse(error.to_string()))?;
        let target_binding = canonical::content_ref(&binding_bytes, "application/json")
            .map_err(|error| refuse(error.to_string()))?;
        let source_context = context_commitment(&source.transcript().origin)?;
        let bytes = encode(&serde_json::json!({
            "schema":"crucible.installed-reader-conditional-association.v1",
            "obligation":obligation,
            "source":source.reference(),
            "source_context":source_context,
            "first_attempt":source.transcript().origin.attempt,
            "first_activation":source.transcript().origin.activation,
            "target_world":target.world_binding_hash(),
            "target_binding":target_binding,
            "target_route":route,
            "host":self.profile.host,
            "native_windows":9,
            "original_input_associations":4,
            "taint":source.transcript().origin.repeatability,
            "scope":"exact original boundary requests and source-scoped native lineage; conditional model only; physical preservation and counterfactual execution refused",
        }))
        .map_err(|error| refuse(error.to_string()))?;
        Ok(ReplayQualification {
            proof: InputPayload {
                reference: canonical::content_ref(&bytes, "application/json")
                    .map_err(|error| refuse(error.to_string()))?,
                bytes,
            },
            source_context,
            target_world: target.world_binding_hash().clone(),
            target_binding,
            target_route: route.clone(),
        })
    }
}

impl InstalledReplayPolicy for ConditionalPolicy {
    fn qualify(
        &self,
        source: &AuthenticatedTranscript,
        target: &AdmittedGraph,
        route: &NodeRoute,
        context: &[InputPayload],
    ) -> Result<ReplayQualification, TranscriptError> {
        self.qualification(source, target, route, context, "original-boundary-replay")
    }

    fn qualify_original_lineage(
        &self,
        source: &AuthenticatedTranscript,
        target: &AdmittedGraph,
        route: &NodeRoute,
        context: &[InputPayload],
    ) -> Result<ReplayQualification, TranscriptError> {
        self.qualification(source, target, route, context, "original-native-lineage")
    }

    fn qualify_original_lineage_continuation(
        &self,
        source: &AuthenticatedTranscript,
        target: &AdmittedGraph,
        route: &NodeRoute,
        context: &[InputPayload],
    ) -> Result<ReplayQualification, TranscriptError> {
        self.qualification(
            source,
            target,
            route,
            context,
            "complete-conditional-runtime7",
        )
    }
}
