//! Installs one independently configured namespace for the fixed collecting fixture.
//!
//! The host names the exact publication, handler and package before Child. Those
//! pins authorize only this finite source programme's semantic interpretation;
//! neither metadata nor this registry can issue ordinary behavioral acceptance.

use super::{InstalledTypedReaderPackage, InstalledTypedReaderSourceFixture};
use crucible::node_admission::*;
use crucible_node_contract::*;
use std::{collections::BTreeSet, rc::Rc};

/// Retains exact host-installed namespace/code interpretation for collecting only.
///
/// The independent host supplies all three identity pins. Package metadata has
/// no constructor path that can choose these pins itself. Ordinary extension
/// application and dependency qualification always refuse.
pub struct TypedReaderCollectingExtensionPolicy {
    source: Rc<InstalledTypedReaderSourceFixture>,
    publication: ContentRef,
    handler: ContentRef,
    semantics: ExtensionSemanticContract,
}

impl TypedReaderCollectingExtensionPolicy {
    /// Installs one exact namespace, handler and all eight source semantic axes.
    ///
    /// This explicit host configuration is restricted to the retained fixture's
    /// complete programme. The publication body remains unqualified data; the
    /// independently supplied pins and owning source installation are conjuncts.
    ///
    /// # Errors
    /// Refuses changed pins, reserved core names, omitted source axes or a schema
    /// other than the measured reader's bounded durable parameter validator.
    pub fn configure(
        expected_package: &ContentRef,
        expected_publication: &ContentRef,
        expected_handler: &ContentRef,
        source: &Rc<InstalledTypedReaderSourceFixture>,
    ) -> Result<Rc<Self>, EvidenceError> {
        let package = source.package();
        let definition = package.definition();
        if package.identity() != expected_package
            || &definition.declaration().owner.publication_origin != expected_publication
            || definition.handler() != expected_handler
            || definition.declaration().identifier.as_str()
                != "org.andyl.reference.original-input-lineage"
        {
            return Err(refused());
        }
        let publication = package
            .definition_objects()
            .get(expected_publication)
            .ok_or_else(refused)?;
        expected_publication.verify(publication).map_err(error)?;
        // This literal is an installed source codec, not a publication assertion
        // of trust. Host-selected exact pins above supply the fixture authority.
        let expected = br#"{"schema":"crucible.reference.lineage-reader-typed.namespace-origin.v1","namespace":"org.andyl.reference","source_policy":"public-original-input-lineage-reader-typed-v2","authority":"unqualified installation data; independent source namespace authority required"}"#;
        if publication.as_slice() != expected {
            return Err(refused());
        }
        let semantics = semantic_contract(package)?;
        Ok(Rc::new(Self {
            source: Rc::clone(source),
            publication: expected_publication.clone(),
            handler: expected_handler.clone(),
            semantics,
        }))
    }

    /// Installs the one exact declaration beneath independently configured pins.
    ///
    /// # Errors
    /// Refuses any publication/semantic/schema drift or exhausted registry credit.
    pub fn install(self: &Rc<Self>) -> Result<InstalledExtensionRegistry, AdmissionError> {
        InstalledExtensionRegistry::install(
            vec![ExtensionRegistration {
                selection: self.source.package().definition().selection().clone(),
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
                maximum_applications: 32,
                maximum_application_bytes: 1024 * 1024,
                maximum_total_application_bytes: 4 * 1024 * 1024,
                maximum_qualification_checks: 128,
            },
        )
    }

    /// Reauthenticates one collecting application against actual source/world custody.
    ///
    /// # Errors
    /// Refuses ordinary/foreign records, changed full world or current bindings,
    /// substituted parameters, schema/handler/axis drift, or unavailable native enrollment.
    pub fn authenticate_collecting_application(
        &self,
        application: &ExtensionApplication<'_>,
        declaration: &ExtensionDeclaration,
        selected: &ExtensionUse,
        semantics: &ExtensionSemanticContract,
    ) -> Result<(), EvidenceError> {
        let package = self.source.package();
        let definition = package.definition();
        if declaration != definition.declaration()
            || semantics != &self.semantics
            || selected != &definition.durable_application()
            || !self
                .semantics
                .locations
                .contains(&application.scope().record_kind())
        {
            return Err(refused());
        }
        self.source
            .authenticate_collection_world(AdmissionRequest {
                world: application.world(),
                descriptors: application.descriptors(),
                bindings: application.bindings(),
                owners: application.owners(),
                requirements: application.requirements(),
            })
            .map_err(error)?;
        let node = application.scope().node().ok_or_else(refused)?;
        let binding = application.binding().ok_or_else(refused)?;
        if &binding.compatibility.node_id != node
            || application.scope().binding_hash()
                != Some(&binding.compatibility.identity().map_err(error)?)
        {
            return Err(refused());
        }
        let source = self.source.source(node).map_err(error)?;
        match application.scope().record_path() {
            ExtensionRecordPath::Node
                if application.scope().record_kind()
                    == ExtensionRecordKind::BindingCompatibility => {}
            ExtensionRecordPath::SelectedFacet { facet }
                if facet.as_str() == "reference-device/quantized-lineage-reader-typed-v2" => {}
            ExtensionRecordPath::AdvertisedFacet { facet }
                if facet.as_str() == "reference-device/quantized-lineage-reader-typed-v2" => {}
            _ => return Err(refused()),
        }
        if application.node() != Some(&source.profile.descriptor)
            || application.mode() != Some(OperatingMode::Quantized)
        {
            return Err(refused());
        }
        self.source.current(node).map_err(error)
    }
}

impl ExtensionInstallationAuthority for TypedReaderCollectingExtensionPolicy {
    fn content(&self, reference: &ContentRef, maximum: usize) -> Result<Vec<u8>, EvidenceError> {
        let bytes = self
            .source
            .package()
            .definition_objects()
            .get(reference)
            .ok_or_else(refused)?;
        if bytes.len() > maximum
            || usize::try_from(reference.length.get()).map_err(error)? > maximum
        {
            return Err(refused());
        }
        reference.verify(bytes).map_err(error)?;
        Ok(bytes.clone())
    }

    fn authenticate_namespace(
        &self,
        declaration: &ExtensionDeclaration,
        selection: &ExtensionSelection,
    ) -> Result<(), EvidenceError> {
        let definition = self.source.package().definition();
        if declaration != definition.declaration()
            || selection != definition.selection()
            || declaration.owner.publication_origin != self.publication
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
        definition: &ContentRef,
    ) -> Result<(), EvidenceError> {
        if !self
            .source
            .package()
            .definition()
            .declaration()
            .dependencies
            .iter()
            .any(|dep| {
                matches!(dep,
            ExtensionDependency::Core { identifier: expected, version: edition, definition: body }
            if expected == identifier && *edition == version && body == definition)
            })
        {
            return Err(refused());
        }
        self.content(definition, 256 * 1024).map(|_| ())
    }

    fn authenticate_schema(&self, schema: &SchemaRef) -> Result<(), EvidenceError> {
        if schema != &self.source.package().definition().declaration().schema {
            return Err(refused());
        }
        self.content(&schema.definition, 256 * 1024).map(|_| ())
    }

    fn authenticate_handler(
        &self,
        declaration: &ExtensionDeclaration,
        handler: &ContentRef,
        semantics: &ExtensionSemanticContract,
    ) -> Result<(), EvidenceError> {
        if declaration != self.source.package().definition().declaration()
            || handler != &self.handler
            || semantics != &self.semantics
        {
            return Err(refused());
        }
        for (path, reference) in self.source.package().runtime_objects() {
            super::package::Artifact {
                path: path.to_path_buf(),
                content: reference.clone(),
            }
            .measure()
            .map_err(error)?;
        }
        Ok(())
    }
}

impl ExtensionSemanticHandler for TypedReaderCollectingExtensionPolicy {
    fn identity(&self) -> &ContentRef {
        &self.handler
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
        self.authenticate_collecting_application(
            application,
            declaration,
            selected,
            &self.semantics,
        )
    }
}

impl ExtensionQualificationAuthority for TypedReaderCollectingExtensionPolicy {
    fn actual_features(
        &self,
        application: &ExtensionApplication<'_>,
        maximum: usize,
    ) -> Result<IdSet, EvidenceError> {
        let definition = self.source.package().definition();
        self.authenticate_collecting_application(
            application,
            definition.declaration(),
            &definition.durable_application(),
            &self.semantics,
        )?;
        let source = self
            .source
            .source(application.scope().node().ok_or_else(refused)?)
            .map_err(error)?;
        let retained = source.features.try_borrow().map_err(error)?;
        let actual = retained.as_ref().ok_or_else(refused)?;
        let required = &definition.declaration().required_features;
        if required.len() > maximum || required.iter().any(|feature| !actual.contains(feature)) {
            return Err(refused());
        }
        Ok(required.clone())
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
        _: &ExtensionApplication<'_>,
        _: &ExtensionDeclaration,
        _: &ExtensionUse,
        _: &ExtensionSemanticContract,
    ) -> Result<(), EvidenceError> {
        Err(refused())
    }
}

fn semantic_contract(
    package: &InstalledTypedReaderPackage,
) -> Result<ExtensionSemanticContract, EvidenceError> {
    let axis = |name: &str| {
        package
            .semantic_contracts()
            .get(name)
            .cloned()
            .ok_or_else(refused)
    };
    Ok(ExtensionSemanticContract {
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
            Id::new("reference-device/quantized-lineage-reader-typed-v2").map_err(error)?,
        ]),
        modes: vec![OperatingMode::Quantized],
        interfaces: BTreeSet::new(),
        impact: ExtensionImpact::Behavior,
    })
}

fn error(error: impl std::fmt::Display) -> EvidenceError {
    EvidenceError {
        message: error.to_string(),
    }
}

fn refused() -> EvidenceError {
    EvidenceError {
        message:
            "typed collecting namespace/application is outside configured original source custody"
                .into(),
    }
}
