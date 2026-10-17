//! Installs exact durable reader selection beneath configured candidate trust.
//!
//! Only facet and compatibility applications are admitted here. The original
//! dynamic InputBatch inventory is checked by the owning source reader at use.

use std::{
    collections::{BTreeMap, BTreeSet},
    rc::Rc,
};

use crucible::node_admission::*;
use crucible_node_contract::*;

use super::{package::InstalledReaderPackage, policy::InstalledReaderPolicy};

pub(super) struct ReaderExtensionPolicy {
    package: Rc<InstalledReaderPackage>,
    profiles: BTreeMap<Id, (NodeBinding, Rc<InstalledReaderPolicy>)>,
    world: WorldBinding,
    semantics: ExtensionSemanticContract,
}

impl ReaderExtensionPolicy {
    /// Binds the exact candidate roster to all eight installed semantic axes.
    ///
    /// # Errors
    /// Refuses an incomplete roster, absent source axis or invalid identifier.
    pub(super) fn new(
        package: Rc<InstalledReaderPackage>,
        world: WorldBinding,
        profiles: BTreeMap<Id, (NodeBinding, Rc<InstalledReaderPolicy>)>,
    ) -> Result<Rc<Self>, EvidenceError> {
        if profiles.len() != 3 {
            return Err(refused());
        }
        let axes = package.definition().axes();
        let axis = |name: &str| axes.get(name).cloned().ok_or_else(refused);
        let semantics = ExtensionSemanticContract {
            class_contract: axis("class")?,
            facet_contract: axis("facet")?,
            mode_contract: axis("mode")?,
            port_contract: axis("port")?,
            timing_contract: axis("timing")?,
            state_contract: axis("state")?,
            error_contract: axis("error")?,
            qualification_contract: axis("qualification")?,
            locations: BTreeSet::from([
                ExtensionRecordKind::FacetSelection,
                ExtensionRecordKind::BindingCompatibility,
            ]),
            roles: BTreeSet::new(),
            facets: BTreeSet::from([
                Id::new("reference-device/quantized-lineage-reader-v1").map_err(|_| refused())?
            ]),
            modes: vec![OperatingMode::Quantized],
            interfaces: BTreeSet::new(),
            impact: ExtensionImpact::Behavior,
        };
        Ok(Rc::new(Self {
            package,
            profiles,
            world,
            semantics,
        }))
    }

    /// Installs the exact durable selection under finite registry credits.
    ///
    /// # Errors
    /// Refuses invalid source roles, namespace or handler checks, unsupported
    /// semantic applications or exhausted registry credits.
    pub(super) fn install(self: &Rc<Self>) -> Result<InstalledExtensionRegistry, AdmissionError> {
        InstalledExtensionRegistry::install(
            vec![ExtensionRegistration {
                selection: self.package.definition().regenerated().selection().clone(),
                handler: self.clone(),
                qualification: self.clone(),
            }],
            self.as_ref(),
            ExtensionRegistryLimits {
                maximum_definitions: 1,
                maximum_objects: 32,
                maximum_object_bytes: 256 * 1024,
                maximum_total_bytes: 1024 * 1024,
                maximum_dependencies: 3,
                maximum_applications: 4096,
                maximum_application_bytes: 1024 * 1024,
                maximum_total_application_bytes: 64 * 1024 * 1024,
                maximum_qualification_checks: 128,
            },
        )
    }

    fn application(
        &self,
        application: &ExtensionApplication<'_>,
        selected: &ExtensionUse,
    ) -> Result<&InstalledReaderPolicy, EvidenceError> {
        if application.world() != &self.world
            || !self
                .semantics
                .locations
                .contains(&application.scope().record_kind())
            || selected
                != &self
                    .package
                    .definition()
                    .regenerated()
                    .durable_application()
        {
            return Err(refused());
        }
        let node = application.scope().node().ok_or_else(refused)?;
        let (expected, policy) = self.profiles.get(node).ok_or_else(refused)?;
        if application
            .bindings()
            .iter()
            .find(|binding| &binding.compatibility.node_id == node)
            != Some(expected)
        {
            return Err(refused());
        }
        let descriptor = application
            .descriptors()
            .iter()
            .find(|descriptor| &descriptor.id == node)
            .ok_or_else(refused)?;
        policy
            .authenticate_descriptor(descriptor)
            .map_err(|_| refused())?;
        Ok(policy)
    }
}

impl ExtensionInstallationAuthority for ReaderExtensionPolicy {
    fn content(&self, reference: &ContentRef, maximum: usize) -> Result<Vec<u8>, EvidenceError> {
        let bytes = self
            .package
            .definition()
            .objects()
            .get(reference)
            .ok_or_else(refused)?;
        if bytes.len() > maximum {
            return Err(refused());
        }
        let mut result = Vec::new();
        result
            .try_reserve_exact(bytes.len())
            .map_err(|_| refused())?;
        result.extend_from_slice(bytes);
        Ok(result)
    }

    fn authenticate_namespace(
        &self,
        declaration: &ExtensionDeclaration,
        selection: &ExtensionSelection,
    ) -> Result<(), EvidenceError> {
        let definition = self.package.definition().regenerated();
        if declaration != definition.declaration()
            || selection != definition.selection()
            || declaration.identifier.as_str().starts_with("cnp.")
        {
            return Err(refused());
        }
        Ok(())
    }

    fn authenticate_core_contract(
        &self,
        identifier: &Id,
        version: u16,
        reference: &ContentRef,
    ) -> Result<(), EvidenceError> {
        if !self
            .package
            .definition()
            .regenerated()
            .declaration()
            .dependencies
            .iter()
            .any(|dependency| match dependency {
                ExtensionDependency::Core {
                    identifier: expected,
                    version: edition,
                    definition,
                } => identifier == expected && version == *edition && reference == definition,
                _ => false,
            })
        {
            return Err(refused());
        }
        Ok(())
    }

    fn authenticate_schema(&self, schema: &SchemaRef) -> Result<(), EvidenceError> {
        if schema != &self.package.definition().regenerated().declaration().schema {
            return Err(refused());
        }
        Ok(())
    }

    fn authenticate_handler(
        &self,
        declaration: &ExtensionDeclaration,
        identity: &ContentRef,
        semantics: &ExtensionSemanticContract,
    ) -> Result<(), EvidenceError> {
        let definition = self.package.definition().regenerated();
        if declaration != definition.declaration()
            || identity != definition.handler()
            || semantics != &self.semantics
        {
            return Err(refused());
        }
        self.package.provider().measure().map_err(|_| refused())?;
        self.package.device().measure().map_err(|_| refused())
    }
}

impl ExtensionSemanticHandler for ReaderExtensionPolicy {
    fn identity(&self) -> &ContentRef {
        self.package.definition().regenerated().handler()
    }

    fn semantics(&self) -> &ExtensionSemanticContract {
        &self.semantics
    }

    fn validate_application(
        &self,
        application: &ExtensionApplication<'_>,
        declaration: &ExtensionDeclaration,
        selected: &ExtensionUse,
    ) -> Result<(), EvidenceError> {
        if declaration != self.package.definition().regenerated().declaration() {
            return Err(refused());
        }
        self.application(application, selected).map(|_| ())
    }
}

impl ExtensionQualificationAuthority for ReaderExtensionPolicy {
    fn actual_features(
        &self,
        application: &ExtensionApplication<'_>,
        maximum: usize,
    ) -> Result<IdSet, EvidenceError> {
        let selected = self
            .package
            .definition()
            .regenerated()
            .durable_application();
        let actual = self
            .application(application, &selected)?
            .negotiated_features(3)
            .map_err(|_| refused())?;
        let required = &self
            .package
            .definition()
            .regenerated()
            .declaration()
            .required_features;
        let selected = actual
            .into_iter()
            .filter(|feature| required.contains(feature))
            .collect::<IdSet>();
        if selected.len() > maximum || &selected != required {
            return Err(refused());
        }
        Ok(selected)
    }

    fn qualify_dependency(
        &self,
        _: &ExtensionApplication<'_>,
        _: &ExtensionUse,
        _: &ExtensionDeclaration,
        _: &ExtensionDeclaration,
        _: &ExtensionSemanticContract,
    ) -> Result<(), EvidenceError> {
        Err(refused())
    }

    fn qualify_application(
        &self,
        application: &ExtensionApplication<'_>,
        declaration: &ExtensionDeclaration,
        selected: &ExtensionUse,
        semantics: &ExtensionSemanticContract,
    ) -> Result<(), EvidenceError> {
        if declaration != self.package.definition().regenerated().declaration()
            || semantics != &self.semantics
        {
            return Err(refused());
        }
        self.application(application, selected)?
            .authenticate_enrolled()
            .map_err(|_| refused())
    }
}

fn refused() -> EvidenceError {
    EvidenceError {
        message: "reader candidate application is outside its measured original installation"
            .into(),
    }
}
