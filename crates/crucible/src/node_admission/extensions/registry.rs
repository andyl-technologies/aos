//! Verifies bounded installed declaration and dependency inventories.

use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use crucible_node_contract::{
    ContentRef, ExtensionDeclaration, ExtensionDependency, ExtensionSelection, Validate, canonical,
};

use crate::node_admission::{AdmissionCode, AdmissionError, AdmissionStage, AdmissionSubject};

use super::authority::{
    ExtensionInstallationAuthority, ExtensionQualificationAuthority, ExtensionSemanticHandler,
};

/// Bounds registry installation and selected application custody before allocation.
#[derive(Clone, Copy, Debug)]
pub struct ExtensionRegistryLimits {
    /// Bounds independently installed exact definitions.
    pub maximum_definitions: usize,
    /// Bounds distinct immutable definition, schema, specification, and code objects.
    pub maximum_objects: usize,
    /// Bounds one immutable definition or contract body.
    pub maximum_object_bytes: usize,
    /// Bounds the complete independently verified publication inventory.
    pub maximum_total_bytes: usize,
    /// Bounds exact dependency edges across the installed inventory.
    pub maximum_dependencies: usize,
    /// Bounds all selected applications in one admitted graph.
    pub maximum_applications: usize,
    /// Bounds one selected use, including parameters and identity fields.
    pub maximum_application_bytes: usize,
    /// Bounds the sum of selected parameter and scope records.
    pub maximum_total_application_bytes: usize,
    /// Bounds direct and transitive semantic/feature/qualification callbacks.
    pub maximum_qualification_checks: usize,
}

impl Default for ExtensionRegistryLimits {
    fn default() -> Self {
        Self {
            maximum_definitions: 256,
            maximum_objects: 4096,
            maximum_object_bytes: 4 * 1024 * 1024,
            maximum_total_bytes: 64 * 1024 * 1024,
            maximum_dependencies: 4096,
            maximum_applications: 65_536,
            maximum_application_bytes: 1024 * 1024,
            maximum_total_application_bytes: 64 * 1024 * 1024,
            maximum_qualification_checks: 1_048_576,
        }
    }
}

impl ExtensionRegistryLimits {
    fn validate(self) -> Result<(), AdmissionError> {
        let hard = Self::default();
        for (actual, ceiling) in [
            (self.maximum_definitions, hard.maximum_definitions),
            (self.maximum_objects, hard.maximum_objects),
            (self.maximum_object_bytes, hard.maximum_object_bytes),
            (self.maximum_total_bytes, hard.maximum_total_bytes),
            (self.maximum_dependencies, hard.maximum_dependencies),
            (self.maximum_applications, hard.maximum_applications),
            (
                self.maximum_application_bytes,
                hard.maximum_application_bytes,
            ),
            (
                self.maximum_total_application_bytes,
                hard.maximum_total_application_bytes,
            ),
            (
                self.maximum_qualification_checks,
                hard.maximum_qualification_checks,
            ),
        ] {
            if actual > ceiling {
                return Err(failure(
                    AdmissionCode::BoundMismatch,
                    "finite registry ceilings",
                    "configured ceiling exceeds supported bound",
                ));
            }
        }
        Ok(())
    }
}

/// Supplies source-installed semantics and independent qualification for one definition.
pub struct ExtensionRegistration {
    /// Selects exact published declaration, version, and parameter-schema identities.
    pub selection: ExtensionSelection,
    /// Supplies actual installed read-only semantic interpretation.
    pub handler: Rc<dyn ExtensionSemanticHandler>,
    /// Supplies independent policy applicable to actual graph applications.
    pub qualification: Rc<dyn ExtensionQualificationAuthority>,
}

pub(super) struct InstalledDefinition {
    pub selection: ExtensionSelection,
    pub declaration: ExtensionDeclaration,
    pub handler: Rc<dyn ExtensionSemanticHandler>,
    pub qualification: Rc<dyn ExtensionQualificationAuthority>,
    pub handler_identity: ContentRef,
    pub semantics: super::ExtensionSemanticContract,
    pub objects: BTreeSet<ContentRef>,
}

/// Holds complete authenticated definitions; installation alone grants no capability.
pub struct InstalledExtensionRegistry {
    pub(super) limits: ExtensionRegistryLimits,
    pub(super) definitions: BTreeMap<ContentRef, InstalledDefinition>,
    pub(super) objects: BTreeMap<ContentRef, Rc<[u8]>>,
}

impl InstalledExtensionRegistry {
    /// Installs bounded exact definitions through configured host trust.
    ///
    /// # Errors
    /// Refuses unknown namespace or code authority, altered publication content,
    /// unsupported schemas, conflicting published versions, omitted or cyclic
    /// dependencies, and any allocation exceeding the supplied finite ceilings.
    pub fn install(
        registrations: Vec<ExtensionRegistration>,
        authority: &dyn ExtensionInstallationAuthority,
        limits: ExtensionRegistryLimits,
    ) -> Result<Self, AdmissionError> {
        limits.validate()?;
        if registrations.len() > limits.maximum_definitions {
            return Err(failure(
                AdmissionCode::BoundMismatch,
                "bounded definitions",
                "too many registered definitions",
            ));
        }

        let mut reader = PublicationReader {
            authority,
            limits,
            objects: BTreeMap::new(),
            consumed: 0,
        };
        let mut definitions: BTreeMap<ContentRef, InstalledDefinition> = BTreeMap::new();
        let mut dependency_count = 0usize;

        for registration in registrations {
            registration.selection.validate().map_err(schema_error)?;
            if definitions.contains_key(&registration.selection.declaration) {
                return Err(failure(
                    AdmissionCode::IdentityMismatch,
                    "one installation per exact declaration",
                    "duplicate declaration installation",
                ));
            }

            let bytes = reader.read(&registration.selection.declaration)?;
            let declaration: ExtensionDeclaration =
                canonical::decode(&bytes, limits.maximum_object_bytes).map_err(schema_error)?;
            declaration.validate().map_err(schema_error)?;
            if declaration.identifier != registration.selection.identifier
                || declaration.semantic_version != registration.selection.semantic_version
                || declaration.schema_digest != registration.selection.schema_digest
            {
                return Err(failure(
                    AdmissionCode::IdentityMismatch,
                    "exact definition selection",
                    "identifier, version, or schema differs from declaration",
                ));
            }
            if definitions.values().any(|installed| {
                installed.selection.identifier == registration.selection.identifier
                    && installed.selection.semantic_version
                        == registration.selection.semantic_version
            }) {
                return Err(failure(
                    AdmissionCode::IdentityMismatch,
                    "immutable published version",
                    "same identifier/version selects different declaration bytes",
                ));
            }

            authority
                .authenticate_namespace(&declaration, &registration.selection)
                .map_err(trust_error)?;
            let semantics = registration.handler.semantics();
            validate_semantics(&declaration, semantics, limits)?;
            authority
                .authenticate_handler(&declaration, registration.handler.identity(), semantics)
                .map_err(trust_error)?;
            authority
                .authenticate_schema(&declaration.schema)
                .map_err(trust_error)?;

            dependency_count = dependency_count
                .checked_add(declaration.dependencies.len())
                .ok_or_else(|| {
                    failure(
                        AdmissionCode::BoundMismatch,
                        "bounded dependencies",
                        "dependency count overflow",
                    )
                })?;
            if dependency_count > limits.maximum_dependencies {
                return Err(failure(
                    AdmissionCode::BoundMismatch,
                    "bounded dependencies",
                    "dependency inventory exceeds ceiling",
                ));
            }

            let mut objects = BTreeSet::new();
            for reference in [
                &registration.selection.declaration,
                &declaration.owner.publication_origin,
                &declaration.schema.definition,
                &declaration.specification,
                &declaration.timing_effects,
                &declaration.state_effects,
                &declaration.error_behavior,
                &declaration.conformance,
                registration.handler.identity(),
                &semantics.class_contract,
                &semantics.facet_contract,
                &semantics.mode_contract,
                &semantics.port_contract,
            ] {
                reader.read(reference)?;
                objects.insert(reference.clone());
            }
            for dependency in &declaration.dependencies {
                if let ExtensionDependency::Core {
                    identifier,
                    version,
                    definition,
                } = dependency
                {
                    authority
                        .authenticate_core_contract(identifier, *version, definition)
                        .map_err(trust_error)?;
                    reader.read(definition)?;
                    objects.insert(definition.clone());
                }
            }

            let handler_identity = registration.handler.identity().clone();
            let semantics = semantics.clone();
            definitions.insert(
                registration.selection.declaration.clone(),
                InstalledDefinition {
                    selection: registration.selection,
                    declaration,
                    handler: registration.handler,
                    qualification: registration.qualification,
                    handler_identity,
                    semantics,
                    objects,
                },
            );
        }

        verify_dependencies(&definitions, limits.maximum_dependencies)?;
        Ok(Self {
            limits,
            definitions,
            objects: reader.objects,
        })
    }

    /// Reports the number of authenticated definitions without implying selection.
    pub fn len(&self) -> usize {
        self.definitions.len()
    }

    /// Reports whether every nonempty extension map must be refused.
    pub fn is_empty(&self) -> bool {
        self.definitions.is_empty()
    }
}

struct PublicationReader<'a> {
    authority: &'a dyn ExtensionInstallationAuthority,
    limits: ExtensionRegistryLimits,
    objects: BTreeMap<ContentRef, Rc<[u8]>>,
    consumed: usize,
}

impl PublicationReader<'_> {
    fn read(&mut self, reference: &ContentRef) -> Result<Rc<[u8]>, AdmissionError> {
        reference.validate().map_err(schema_error)?;
        if let Some(bytes) = self.objects.get(reference) {
            return Ok(Rc::clone(bytes));
        }
        let length = usize::try_from(reference.length.get()).map_err(|_| {
            failure(
                AdmissionCode::BoundMismatch,
                "representable content size",
                "content length exceeds address space",
            )
        })?;
        let total = self.consumed.checked_add(length).ok_or_else(|| {
            failure(
                AdmissionCode::BoundMismatch,
                "bounded publication bytes",
                "publication length overflow",
            )
        })?;
        if self.objects.len() >= self.limits.maximum_objects
            || length > self.limits.maximum_object_bytes
            || total > self.limits.maximum_total_bytes
        {
            return Err(failure(
                AdmissionCode::BoundMismatch,
                "preallocated publication credit",
                "content exceeds remaining object or byte credit",
            ));
        }
        // The trusted reader receives the reserved ceiling before it allocates.
        let bytes = self
            .authority
            .content(reference, length)
            .map_err(trust_error)?;
        reference.verify(&bytes).map_err(schema_error)?;
        let bytes: Rc<[u8]> = bytes.into();
        self.objects.insert(reference.clone(), Rc::clone(&bytes));
        self.consumed = total;
        Ok(bytes)
    }
}

fn validate_semantics(
    declaration: &ExtensionDeclaration,
    semantics: &super::ExtensionSemanticContract,
    limits: ExtensionRegistryLimits,
) -> Result<(), AdmissionError> {
    if semantics.locations.is_empty()
        || semantics.locations.len() > 17
        || semantics.roles.len() > limits.maximum_definitions
        || semantics.facets.len() > limits.maximum_definitions
        || semantics.interfaces.len() > limits.maximum_definitions
        || semantics.modes.len() > 2
        || semantics.modes.windows(2).any(|pair| {
            pair[0] == pair[1] || pair[0] == crucible_node_contract::OperatingMode::Quantized
        })
    {
        return Err(failure(
            AdmissionCode::InvalidSchema,
            "closed bounded semantic scope",
            "unsupported semantic selector inventory",
        ));
    }
    if semantics.timing_contract != declaration.timing_effects
        || semantics.state_contract != declaration.state_effects
        || semantics.error_contract != declaration.error_behavior
        || semantics.qualification_contract != declaration.conformance
    {
        return Err(failure(
            AdmissionCode::IdentityMismatch,
            "complete installed semantic identities",
            "timing, state, error, or qualification contract differs",
        ));
    }
    let allowances = &declaration.limits;
    if allowances.maximum_message_bytes.get() > limits.maximum_application_bytes as u64
        || allowances.maximum_allocation_bytes.get() > limits.maximum_total_application_bytes as u64
        || allowances.maximum_message_bytes > allowances.maximum_allocation_bytes
        || allowances.maximum_objects.get() > limits.maximum_applications as u64
        || allowances.maximum_pending_events.get() > limits.maximum_applications as u64
        || allowances.maximum_operations.get() > limits.maximum_applications as u64
    {
        return Err(failure(
            AdmissionCode::BoundMismatch,
            "supported finite extension allowances",
            "declared allowances exceed host-supported ceilings",
        ));
    }
    Ok(())
}

fn verify_dependencies(
    definitions: &BTreeMap<ContentRef, InstalledDefinition>,
    maximum_edges: usize,
) -> Result<(), AdmissionError> {
    for installed in definitions.values() {
        let mut ancestors = BTreeSet::new();
        let mut visited = BTreeSet::new();
        let mut stack = vec![(&installed.selection.declaration, false)];
        let mut edges = 0usize;
        while let Some((reference, leaving)) = stack.pop() {
            if leaving {
                ancestors.remove(reference);
                visited.insert(reference);
                continue;
            }
            if ancestors.contains(reference) {
                return Err(failure(
                    AdmissionCode::InvalidSchema,
                    "acyclic exact dependencies",
                    "dependency cycle is unsupported",
                ));
            }
            if visited.contains(reference) {
                continue;
            }
            let entry = definitions.get(reference).ok_or_else(|| {
                failure(
                    AdmissionCode::UnknownInterface,
                    "installed dependency closure",
                    "dependency is not installed",
                )
            })?;
            ancestors.insert(reference);
            stack.push((reference, true));
            for dependency in entry.declaration.dependencies.iter().rev() {
                if let ExtensionDependency::Extension { selection } = dependency {
                    let actual = definitions.get(&selection.declaration).ok_or_else(|| {
                        failure(
                            AdmissionCode::UnknownInterface,
                            "installed dependency closure",
                            "extension prerequisite is absent",
                        )
                    })?;
                    if &actual.selection != selection {
                        return Err(failure(
                            AdmissionCode::IdentityMismatch,
                            "exact prerequisite selection",
                            "dependency version or schema differs",
                        ));
                    }
                    edges = edges.checked_add(1).ok_or_else(|| {
                        failure(
                            AdmissionCode::BoundMismatch,
                            "bounded dependency traversal",
                            "dependency edge overflow",
                        )
                    })?;
                    if edges > maximum_edges {
                        return Err(failure(
                            AdmissionCode::BoundMismatch,
                            "bounded dependency traversal",
                            "dependency traversal exceeds reserved credit",
                        ));
                    }
                    stack.push((&selection.declaration, false));
                }
            }
        }
    }
    Ok(())
}

pub(super) fn failure(code: AdmissionCode, required: &str, observed: &str) -> AdmissionError {
    crate::node_admission::error::refuse(
        AdmissionStage::Authenticate,
        AdmissionSubject::World,
        code,
        required,
        observed,
    )
}

pub(super) fn schema_error(error: crucible_node_contract::ContractError) -> AdmissionError {
    failure(
        AdmissionCode::InvalidSchema,
        "supported exact extension schema/content",
        &error.to_string(),
    )
}

pub(super) fn trust_error(error: crate::node_admission::EvidenceError) -> AdmissionError {
    failure(
        AdmissionCode::QualificationUnavailable,
        "authenticated installed extension semantics",
        &error.message,
    )
}
