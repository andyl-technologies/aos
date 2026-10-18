//! Borrowed persistence projections without cloned signal or binding graphs.

use serde::ser::{SerializeSeq, SerializeStruct};
use serde::{Serialize, Serializer};

use super::*;

pub(in crate::model::fault_signal) struct PlanWireRef<'a>(pub &'a FaultSignalPlan);

impl Serialize for PlanWireRef<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut row = serializer.serialize_struct("FaultSignalPlanWire", 4)?;
        row.serialize_field("semantic_version", &FAULT_SIGNAL_PLAN_WIRE_VERSION)?;
        row.serialize_field("resource_limits", &self.0.resource_limits())?;
        row.serialize_field("signal_program", &Programs(self.0.programs()))?;
        row.serialize_field("fault_binding", &Bindings(self.0.bindings()))?;
        row.end()
    }
}

struct Programs<'a>(&'a [SignalProgram]);

impl Serialize for Programs<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for program in self.0 {
            sequence.serialize_element(&Program(program))?;
        }
        sequence.end()
    }
}

struct Program<'a>(&'a SignalProgram);

impl Serialize for Program<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut row = serializer.serialize_struct("SignalProgramWire", 2)?;
        row.serialize_field("node", self.0.nodes())?;
        row.serialize_field("exported_output", self.0.exported_outputs())?;
        row.end()
    }
}

struct Bindings<'a>(&'a [FaultBinding]);

impl Serialize for Bindings<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for binding in self.0 {
            sequence.serialize_element(&Binding(binding))?;
        }
        sequence.end()
    }
}

struct Binding<'a>(&'a FaultBinding);

impl Serialize for Binding<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut row = serializer.serialize_struct("FaultBindingWire", 13)?;
        row.serialize_field("id", self.0.id())?;
        row.serialize_field("program", &self.0.program())?;
        row.serialize_field("signals", self.0.signals())?;
        row.serialize_field("sampling", self.0.sampling())?;
        row.serialize_field("mapping", self.0.mapping())?;
        row.serialize_field("selector", self.0.selector())?;
        row.serialize_field("phases", self.0.phases())?;
        row.serialize_field("effect", &Effect(self.0.effect()))?;
        row.serialize_field("opportunity_filter", &self.0.opportunity_filter())?;
        row.serialize_field("search", self.0.search())?;
        row.serialize_field("observability", &self.0.observability())?;
        row.serialize_field(
            "transition_declaration",
            &self.0.transition_declaration().map(Transition),
        )?;
        row.serialize_field("service_declaration", &self.0.service_declaration())?;
        row.end()
    }
}

struct Effect<'a>(&'a EffectRequest);

impl Serialize for Effect<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut row = serializer.serialize_struct("EffectRequestWire", 3)?;
        row.serialize_field("semantic_version", &EFFECT_SEMANTIC_VERSION)?;
        row.serialize_field("lifetime", &self.0.lifetime())?;
        row.serialize_field("specification", self.0.specification())?;
        row.end()
    }
}

struct Transition<'a>(&'a StateTransitionTableDeclaration);

impl Serialize for Transition<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut row = serializer.serialize_struct("StateTransitionTableWire", 6)?;
        row.serialize_field("id", &self.0.id)?;
        row.serialize_field("semantic_version", &self.0.semantic_version)?;
        row.serialize_field("input", &self.0.input)?;
        row.serialize_field("effect", &self.0.effect)?;
        row.serialize_field("transition", &Transitions(&self.0.transitions))?;
        row.serialize_field("default_transition", &self.0.default_transition)?;
        row.end()
    }
}

struct Transitions<'a>(&'a BTreeMap<SignalValue, FaultObjectId>);

impl Serialize for Transitions<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for (request, transition) in self.0 {
            sequence.serialize_element(&TransitionEntry {
                request,
                transition,
            })?;
        }
        sequence.end()
    }
}

#[derive(Serialize)]
struct TransitionEntry<'a> {
    request: &'a SignalValue,
    transition: &'a FaultObjectId,
}
