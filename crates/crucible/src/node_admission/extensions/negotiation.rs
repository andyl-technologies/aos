//! Projects source-authenticated registry contracts for versioned peer negotiation.
//!
//! This projection proves installed interpretation identity, not application
//! qualification. Durable graph uses and dynamic Input readers retain their
//! independent installed semantic and behavioral admission requirements.

use std::rc::Rc;

use crucible_node_contract::{
    ContentRef, ExtensionDeclaration, ExtensionDependency, ExtensionSelection, IdSet, Validate,
};
use crucible_node_provider::{
    ProviderError,
    handshake::{
        InstalledExtensionNegotiationVerifier, MAXIMUM_EXTENSION_NEGOTIATION_BYTES,
        MAXIMUM_NEGOTIATED_EXTENSIONS,
    },
};
use serde::Serialize;

use super::{ExtensionSemanticContract, InstalledExtensionRegistry};
use crate::node_admission::evidence::bounded_core;

/// Retains an exact source-installed peer policy without granting graph authority.
pub struct InstalledExtensionPeerPolicy {
    registry: Rc<InstalledExtensionRegistry>,
    supported: Vec<ExtensionSelection>,
    required: Vec<ExtensionSelection>,
}

impl InstalledExtensionPeerPolicy {
    /// Projects explicit exact candidates from an independently installed registry.
    ///
    /// One candidate per identifier makes version choice explicit. Every tuple
    /// must name the exact installed declaration, schema and source handler;
    /// caller-supplied claims cannot install or requalify a definition.
    ///
    /// # Errors
    /// Refuses unknown definitions, altered identity, ambiguous versions,
    /// unsupported requirements, or aggregate encoded policy credit exhaustion.
    pub fn new(
        registry: Rc<InstalledExtensionRegistry>,
        supported: &[ExtensionSelection],
        required: &[ExtensionSelection],
    ) -> Result<Self, ProviderError> {
        validate_roster(supported)?;
        validate_roster(required)?;
        #[derive(Serialize)]
        struct Projection<'a> {
            supported: &'a [ExtensionSelection],
            required: &'a [ExtensionSelection],
        }
        // Count the complete borrowed projection before retaining any tuple.
        bounded_core(
            &Projection {
                supported,
                required,
            },
            MAXIMUM_EXTENSION_NEGOTIATION_BYTES,
        )
        .map_err(|_| ProviderError::ResourceExhausted("installed peer projection bytes"))?;
        for selection in supported {
            installed(&registry, selection)?;
        }
        if required
            .iter()
            .any(|selection| !supported.contains(selection))
        {
            return Err(ProviderError::Correlation(
                "mandatory extension is outside installed peer candidates",
            ));
        }

        let mut supported_copy = Vec::new();
        supported_copy
            .try_reserve_exact(supported.len())
            .map_err(|_| ProviderError::ResourceExhausted("installed peer candidate roster"))?;
        let mut required_copy = Vec::new();
        required_copy
            .try_reserve_exact(required.len())
            .map_err(|_| ProviderError::ResourceExhausted("installed peer requirement roster"))?;
        supported_copy.extend_from_slice(supported);
        required_copy.extend_from_slice(required);
        Ok(Self {
            registry,
            supported: supported_copy,
            required: required_copy,
        })
    }

    /// Projects the complete frozen definition roster of an actually admitted set.
    ///
    /// Every selected prerequisite is required. The installed registry must retain
    /// exactly the handler and semantic contracts frozen by graph admission;
    /// current defaults cannot substitute for an original selected interpretation.
    ///
    /// # Errors
    /// Refuses oversized or ambiguous rosters, uninstalled definitions, changed
    /// source handlers/contracts, or exhausted complete projection byte credit.
    pub fn from_admitted_set(
        registry: Rc<InstalledExtensionRegistry>,
        selected: &super::AdmittedExtensionSet,
    ) -> Result<Self, ProviderError> {
        let count = selected.definitions().len();
        if count > MAXIMUM_NEGOTIATED_EXTENSIONS {
            return Err(ProviderError::ResourceExhausted(
                "admitted peer definition roster",
            ));
        }
        let mut borrowed = Vec::new();
        borrowed
            .try_reserve_exact(count)
            .map_err(|_| ProviderError::ResourceExhausted("borrowed admitted peer definitions"))?;
        for definition in selected.definitions() {
            let current = installed(&registry, definition.selection())?;
            if &current.handler_identity != definition.handler_identity()
                || &current.semantics != definition.semantic_contract()
            {
                return Err(ProviderError::Correlation(
                    "installed peer interpretation differs from original admitted set",
                ));
            }
            borrowed.push(definition.selection());
        }
        borrowed.sort_by(|left, right| left.identifier.cmp(&right.identifier));
        #[derive(Serialize)]
        struct BorrowedProjection<'a> {
            supported: &'a [&'a ExtensionSelection],
            required: &'a [&'a ExtensionSelection],
        }
        bounded_core(
            &BorrowedProjection {
                supported: &borrowed,
                required: &borrowed,
            },
            MAXIMUM_EXTENSION_NEGOTIATION_BYTES,
        )
        .map_err(|_| ProviderError::ResourceExhausted("admitted complete peer projection"))?;
        let mut roster = Vec::new();
        roster
            .try_reserve_exact(count)
            .map_err(|_| ProviderError::ResourceExhausted("admitted peer selection copies"))?;
        for selection in borrowed {
            roster.push(selection.clone());
        }
        Self::new(registry, &roster, &roster)
    }

    /// Borrows an exact installed declaration and its source-authenticated handler.
    ///
    /// The returned contracts are installed metadata; they cannot authorize a
    /// facet application, dynamic control body, native permission or capture.
    ///
    /// # Errors
    /// Refuses a tuple outside this bounded projected source policy.
    pub fn contract(
        &self,
        selection: &ExtensionSelection,
    ) -> Result<
        (
            &ExtensionDeclaration,
            &ContentRef,
            &ExtensionSemanticContract,
        ),
        ProviderError,
    > {
        if !self.supported.contains(selection) {
            return Err(ProviderError::Correlation(
                "extension is outside projected installed policy",
            ));
        }
        let definition = installed(&self.registry, selection)?;
        Ok((
            &definition.declaration,
            &definition.handler_identity,
            &definition.semantics,
        ))
    }
}

impl InstalledExtensionNegotiationVerifier for InstalledExtensionPeerPolicy {
    fn supported(&self) -> &[ExtensionSelection] {
        &self.supported
    }

    fn required(&self) -> &[ExtensionSelection] {
        &self.required
    }

    fn verify_selection(
        &self,
        selected: &[ExtensionSelection],
        features: &IdSet,
    ) -> Result<(), ProviderError> {
        validate_roster(selected)?;
        features.validate()?;
        if self
            .required
            .iter()
            .any(|required| !selected.contains(required))
        {
            return Err(ProviderError::Correlation(
                "peer omitted mandatory installed extension",
            ));
        }
        for selection in selected {
            let (declaration, _, _) = self.contract(selection)?;
            if declaration
                .required_features
                .iter()
                .any(|feature| !features.contains(feature))
            {
                return Err(ProviderError::Correlation(
                    "extension required feature was not negotiated",
                ));
            }
            for dependency in &declaration.dependencies {
                if let ExtensionDependency::Extension { selection } = dependency
                    && !selected.contains(selection)
                {
                    return Err(ProviderError::Correlation(
                        "peer omitted exact installed extension dependency",
                    ));
                }
            }
        }
        Ok(())
    }
}

fn installed<'a>(
    registry: &'a InstalledExtensionRegistry,
    selection: &ExtensionSelection,
) -> Result<&'a super::registry::InstalledDefinition, ProviderError> {
    selection.validate()?;
    let definition = registry
        .definitions
        .get(&selection.declaration)
        .filter(|definition| &definition.selection == selection)
        .ok_or(ProviderError::Correlation(
            "exact peer extension definition is not installed",
        ))?;
    if definition.handler.identity() != &definition.handler_identity
        || definition.handler.semantics() != &definition.semantics
    {
        return Err(ProviderError::Correlation(
            "source-installed peer handler identity or contracts changed",
        ));
    }
    Ok(definition)
}

fn validate_roster(roster: &[ExtensionSelection]) -> Result<(), ProviderError> {
    if roster.len() > MAXIMUM_NEGOTIATED_EXTENSIONS
        || roster
            .windows(2)
            .any(|pair| pair[0].identifier >= pair[1].identifier)
    {
        return Err(ProviderError::Correlation(
            "ambiguous or oversized installed peer roster",
        ));
    }
    for selection in roster {
        selection.validate()?;
    }
    Ok(())
}
