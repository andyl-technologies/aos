//! Resolves a distinct installed Clock metadata and durable-native profile.
//!
//! Ordinary Clock, CNP Clock and mixed CPU worlds retain their existing profile
//! and archive contracts. This opt-in world uses a source-owned exact metadata
//! handler and the unchanged actual native Clock continuation codec.

mod native;
mod policy;
mod staging;

#[cfg(test)]
mod tests;

use std::rc::Rc;

use crucible::{
    node_admission::{
        AdmissionEvidence, EvidenceError, InstalledExtensionRegistry, QualificationClaim,
    },
    node_contract::{ActivationRecord, SavedRuntimeActivation},
    node_state::{CaptureEvidence, NativeArchiveRecord, StateError, StateErrorCode},
};
use crucible_campaign::ExecutionId;
use crucible_node_contract::*;

use super::{
    InstalledNodeCatalog, InstalledNodeKind, InstalledNodeSelection, InstalledPreparedWorld,
    NodeObservedError, PreparationSource,
};

pub use native::InstalledClockLabelFactory;
pub(super) use policy::ClockLabelPolicy;

/// Holds a source-installed, closed Clock metadata and preservation selection.
///
/// The value is regenerated from the currently measured installation. It has
/// no public constructor and cannot enroll arbitrary declarations, handlers,
/// state effects or imported live authority. Native restoration authenticates
/// the signed original selection separately before allocating a fresh Clock.
#[derive(Clone)]
pub struct InstalledClockLabelProfile {
    policy: Rc<ClockLabelPolicy>,
}

impl InstalledClockLabelProfile {
    /// Borrows the complete original immutable world carrying the fixed label.
    pub fn scenario(&self) -> &crate::node_scenario::NodeScenario {
        &self.policy.labeled
    }
}

impl InstalledNodeCatalog {
    /// Resolves the distinct installed metadata-label Clock profile.
    ///
    /// # Errors
    /// Refuses changed installation artifacts or an unavailable closed Clock
    /// qualification, handler, declaration, schema or preservation contract.
    pub fn installed_clock_label(&self) -> Result<InstalledClockLabelProfile, NodeObservedError> {
        Ok(InstalledClockLabelProfile {
            policy: self.clock_label_profile()?,
        })
    }

    /// Prepares the selected actual Clock under complete inactive world custody.
    ///
    /// A supplied source keeps its original immutable selection and capture cut;
    /// fresh live owner identities never rewrite the durable application scope.
    /// Native execution still requires the complete runtime activation barrier.
    ///
    /// # Errors
    /// Refuses stale installations, altered profile bytes, mismatched original
    /// source worlds, unsupported codecs or unavailable native retirement slots.
    pub fn prepare_installed_clock_label(
        &mut self,
        profile: &InstalledClockLabelProfile,
        execution: ExecutionId,
        source: Option<&NativeArchiveRecord>,
    ) -> Result<(InstalledPreparedWorld, ActivationRecord), NodeObservedError> {
        self.prepare_clock_label(profile.policy.as_ref(), execution, source)
    }

    /// Resolves native archive authentication for this installed Clock profile.
    ///
    /// The resulting factory also supplies its exact immutable CaptureEvidence.
    /// A public digest or an imported archive cannot construct another policy.
    ///
    /// # Errors
    /// Refuses a stale or altered profile, changed host executable, unavailable
    /// native source qualification or unsupported immutable model closure.
    pub fn installed_clock_label_factory(
        &self,
        profile: &InstalledClockLabelProfile,
    ) -> Result<Rc<InstalledClockLabelFactory>, NodeObservedError> {
        let actual = self.clock_label_profile()?;
        if profile.scenario().canonical_bytes()? != actual.labeled.canonical_bytes()? {
            return Err(observed_refusal(
                "Clock label profile differs from current installation",
            ));
        }
        self.clock_label_factory(actual)
    }

    pub(super) fn clock_label_profile(&self) -> Result<Rc<ClockLabelPolicy>, NodeObservedError> {
        let selection = selections()?;
        ClockLabelPolicy::new(self.scenario(&selection)?, &self.host_identity)
    }

    pub(super) fn prepare_clock_label(
        &mut self,
        profile: &ClockLabelPolicy,
        execution: ExecutionId,
        source: Option<&NativeArchiveRecord>,
    ) -> Result<(InstalledPreparedWorld, ActivationRecord), NodeObservedError> {
        let expected = self.clock_label_profile()?;
        if profile.labeled.canonical_bytes()? != expected.labeled.canonical_bytes()? {
            return Err(observed_refusal(
                "authored label profile differs from installed source",
            ));
        }
        let original: Option<SavedRuntimeActivation> = source
            .map(NativeArchiveRecord::source_activation)
            .transpose()
            .map_err(observed_refusal)?;
        let world_identity = profile.labeled.world.identity()?;
        if source.is_some_and(|source| source.manifest().world_binding_hash != world_identity) {
            return Err(observed_refusal("Clock label source world differs"));
        }
        let boundary = source.map(|source| source.manifest().cut);
        let artifacts = self.artifacts.clone();
        self.prepare_world_with_selected_label(
            &selections()?,
            profile.labeled.clone(),
            execution,
            &artifacts,
            None,
            super::SelectedPreparation {
                source: PreparationSource {
                    activation: original.as_ref(),
                    preserved_cut: boundary,
                },
                label: Some(profile),
            },
        )
    }

    pub(super) fn clock_label_factory(
        &self,
        profile: Rc<ClockLabelPolicy>,
    ) -> Result<Rc<InstalledClockLabelFactory>, NodeObservedError> {
        let installed = self.host_state_factory(&selections()?, &profile.base)?;
        Ok(Rc::new(InstalledClockLabelFactory { profile, installed }))
    }
}

// Labels never select a dynamic node or executable. The complete source-owned
// single-Clock roster is regenerated before either live or cold enrollment.
fn selections() -> Result<Vec<InstalledNodeSelection>, NodeObservedError> {
    Ok(vec![InstalledNodeSelection {
        node: Id::new("clock")?,
        owner: Id::new("owner/clock")?,
        kind: InstalledNodeKind::HostClock,
    }])
}

/// Forwards genuine enrolled native qualification while adding one exact registry.
pub(super) struct LabelAdmission<'a> {
    pub(super) original: &'a super::trust::InstalledEvidence,
    pub(super) registry: &'a InstalledExtensionRegistry,
}

impl AdmissionEvidence for LabelAdmission<'_> {
    fn extension_registry(&self) -> Option<&InstalledExtensionRegistry> {
        Some(self.registry)
    }
    fn content(&self, r: &ContentRef, max: usize) -> Result<Vec<u8>, EvidenceError> {
        self.original.content(r, max)
    }
    fn authenticate_implementation(&self, i: &ImplementationIdentity) -> Result<(), EvidenceError> {
        self.original.authenticate_implementation(i)
    }
    fn authenticate_authority(&self, b: &NodeBinding) -> Result<(), EvidenceError> {
        self.original.authenticate_authority(b)
    }
    fn authenticate_schema(&self, s: &SchemaRef) -> Result<(), EvidenceError> {
        self.original.authenticate_schema(s)
    }
    fn qualify(&self, c: QualificationClaim<'_>) -> Result<(), EvidenceError> {
        self.original.qualify(c)
    }
}

impl CaptureEvidence for InstalledClockLabelFactory {
    fn content(&self, r: &ContentRef, max: usize) -> Result<Vec<u8>, StateError> {
        if self.profile.objects.contains_key(r) {
            return crucible::node_admission::ExtensionInstallationAuthority::content(
                self.profile.as_ref(),
                r,
                max,
            )
            .map_err(state_error);
        }
        self.installed.content(r, max)
    }

    fn dependencies(
        &self,
        r: &ContentRef,
        b: &[u8],
        max: usize,
    ) -> Result<Vec<ContentRef>, StateError> {
        if r == &self.profile.labeled.world.scenario_ref {
            if self.profile.objects.get(r).map(Vec::as_slice) != Some(b) || max < 2 {
                return Err(state_error(
                    "installed label scenario body or edge credit differs",
                ));
            }
            let mut deps = vec![
                self.profile.base.world.scenario_ref.clone(),
                self.profile.selection.declaration.clone(),
            ];
            deps.sort();
            deps.dedup();
            return Ok(deps);
        }
        if self.profile.objects.contains_key(r) {
            if self.profile.objects.get(r).map(Vec::as_slice) != Some(b) {
                return Err(state_error("installed label body changed"));
            }
            if r == &self.profile.selection.declaration {
                let d = &self.profile.declaration;
                let mut deps = vec![
                    d.owner.publication_origin.clone(),
                    d.schema.definition.clone(),
                    d.specification.clone(),
                    d.timing_effects.clone(),
                    d.state_effects.clone(),
                    d.error_behavior.clone(),
                    d.conformance.clone(),
                ];
                deps.sort();
                deps.dedup();
                if deps.len() > max {
                    return Err(state_error("installed label dependency edge credit"));
                }
                return Ok(deps);
            }
            return Ok(vec![]);
        }
        self.installed.dependencies(r, b, max)
    }

    fn verify_owner_capture(
        &self,
        _: &crucible::node_admission::AdmittedGraph,
        _: &CaptureManifest,
        _: &CapturedOwner,
        _: &crucible::node_state::StateRequirements,
        _: &crucible::node_state::VerifiedStateContent,
    ) -> Result<crucible::node_state::NativeOwnerCaptureProof, StateError> {
        Err(state_error(
            "immutable label resolver cannot issue native capture proof",
        ))
    }

    fn verify_coordinator_capture(
        &self,
        _: &crucible::node_admission::AdmittedGraph,
        _: &CaptureManifest,
        _: &crucible::node_state::VerifiedStateContent,
    ) -> Result<crucible::node_state::NativeCoordinatorCaptureProof, StateError> {
        Err(state_error(
            "immutable label resolver cannot issue coordinator capture proof",
        ))
    }
}

fn fail(reason: impl Into<String>) -> EvidenceError {
    EvidenceError {
        message: reason.into(),
    }
}
fn state_error(reason: impl std::fmt::Display) -> StateError {
    StateError::new(
        StateErrorCode::NativeEvidence,
        "installed Clock label",
        reason.to_string(),
    )
}
fn observed_refusal(reason: impl std::fmt::Display) -> NodeObservedError {
    super::refused(&reason.to_string())
}
fn measure_current_host(expected: &ContentRef) -> Result<(), NodeObservedError> {
    if super::measure_executable(std::path::Path::new("/proc/self/exe"))? != *expected {
        return Err(observed_refusal(
            "source-installed label executable changed",
        ));
    }
    Ok(())
}
