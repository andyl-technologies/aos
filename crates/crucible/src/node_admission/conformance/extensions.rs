//! Delegates only collecting-purpose extension qualification under current custody.

use crucible_node_contract::{ExtensionDeclaration, ExtensionUse};

use super::*;

impl InstalledConformancePlan {
    pub(in crate::node_admission) fn authenticate_extension_scope(
        &self,
        application: &ExtensionApplication<'_>,
    ) -> Result<(), EvidenceError> {
        self.reauthenticate()?;
        if application
            .world()
            .identity()
            .map_err(|error| failure(error.to_string()))?
            != self.0.world
        {
            return Err(failure("foreign original collection extension world"));
        }
        self.0.authority.authenticate_collection_world(
            self.evidence(),
            AdmissionRequest {
                world: application.world(),
                descriptors: application.descriptors(),
                bindings: application.bindings(),
                owners: application.owners(),
                requirements: application.requirements(),
            },
        )
    }

    pub(in crate::node_admission) fn authenticate_extension_application(
        &self,
        application: &ExtensionApplication<'_>,
        declaration: &ExtensionDeclaration,
        selected: &ExtensionUse,
        semantics: &ExtensionSemanticContract,
    ) -> Result<(), EvidenceError> {
        self.authenticate_extension_scope(application)?;
        self.0.authority.authenticate_collection_extension(
            self.evidence(),
            application,
            declaration,
            selected,
            semantics,
        )?;
        self.authenticate_extension_scope(application)
    }

    pub(in crate::node_admission) fn authenticate_extension_dependency(
        &self,
        application: &ExtensionApplication<'_>,
        selected: &ExtensionUse,
        dependent: &ExtensionDeclaration,
        prerequisite: &ExtensionDeclaration,
        semantics: &ExtensionSemanticContract,
    ) -> Result<(), EvidenceError> {
        self.authenticate_extension_scope(application)?;
        self.0
            .authority
            .authenticate_collection_extension_dependency(
                self.evidence(),
                application,
                selected,
                dependent,
                prerequisite,
                semantics,
            )?;
        self.authenticate_extension_scope(application)
    }
}
