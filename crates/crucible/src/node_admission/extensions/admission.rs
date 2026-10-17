//! Couples registered semantics to actual whole-graph admission records.

use crucible_node_contract::{Extensions, HashRef};
use serde::Serialize;

use crate::node_admission::{
    AdmissionError, AdmissionLimits, AdmissionRequest, InstalledConformancePlan,
};

use super::context::{ExtensionApplication, RecordPlacement};
use super::{AdmittedExtensionSet, InstalledExtensionRegistry};

pub(in crate::node_admission) struct ExtensionAdmission<'a> {
    registry: &'a InstalledExtensionRegistry,
    request: AdmissionRequest<'a>,
    world_hash: HashRef,
    selected: AdmittedExtensionSet,
    collection: Option<&'a InstalledConformancePlan>,
}

impl<'a> ExtensionAdmission<'a> {
    pub fn new(
        registry: &'a InstalledExtensionRegistry,
        request: AdmissionRequest<'a>,
        world_hash: HashRef,
        collection: Option<&'a InstalledConformancePlan>,
    ) -> Self {
        Self {
            registry,
            request,
            world_hash,
            selected: AdmittedExtensionSet::default(),
            collection,
        }
    }

    /// Admits nonempty extension semantics for one original graph record.
    ///
    /// # Errors
    /// Refuses an invalid bounded application or semantics unsupported by the installed registry.
    pub fn check(
        &mut self,
        record: &impl Serialize,
        extensions: &Extensions,
        placement: RecordPlacement<'_>,
        limits: AdmissionLimits,
    ) -> Result<(), AdmissionError> {
        if extensions.is_empty() {
            return Ok(());
        }
        let application = ExtensionApplication::for_record(
            &self.request,
            &self.world_hash,
            record,
            extensions,
            placement,
            limits,
        )?;
        match self.collection {
            Some(plan) => self.registry.admit_map_for_purpose(
                &application,
                extensions,
                &mut self.selected,
                Some(plan),
            ),
            None => self
                .registry
                .admit_map(&application, extensions, &mut self.selected),
        }
    }

    pub fn into_selected(self) -> AdmittedExtensionSet {
        self.selected
    }
}
