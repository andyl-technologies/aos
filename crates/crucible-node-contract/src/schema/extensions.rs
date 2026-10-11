//! Portable exact extension declarations and selections without installed authority.
//!
//! ```json
//! { "major": "1", "minor": "0", "patch": "0", "prerelease": null, "build": null }
//! ```
//!
//! An identity-bearing extension map stores an `ExtensionUse` under its exact
//! identifier. Namespace trust, complete referenced definitions, actual semantic
//! handlers, negotiation, and behavioral qualification require host admission.

use super::*;

/// Selects one exact published Semantic Version, including prerelease and build.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticVersion {
    /// Selects the canonical nonnegative major version.
    pub major: U64,
    /// Selects the canonical nonnegative minor version.
    pub minor: U64,
    /// Selects the canonical nonnegative patch version.
    pub patch: U64,
    /// Retains exact prerelease identifiers; numeric identifiers have no leading zero.
    #[serde(deserialize_with = "required_nullable")]
    pub prerelease: Option<String>,
    /// Retains exact build identifiers as part of this published content selection.
    #[serde(deserialize_with = "required_nullable")]
    pub build: Option<String>,
}

impl Validate for SemanticVersion {
    fn validate(&self) -> Result<(), ContractError> {
        for (field, suffix, numeric_zero_rule) in [
            ("semantic_version.prerelease", &self.prerelease, true),
            ("semantic_version.build", &self.build, false),
        ] {
            if let Some(suffix) = suffix
                && (suffix.is_empty()
                    || suffix.len() > 128
                    || suffix.split('.').any(|part| {
                        part.is_empty()
                            || !part
                                .bytes()
                                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                            || (numeric_zero_rule
                                && part.len() > 1
                                && part.starts_with('0')
                                && part.bytes().all(|byte| byte.is_ascii_digit()))
                    }))
            {
                return Err(invalid(field, "expected bounded exact SemVer identifiers"));
            }
        }
        Ok(())
    }
}

/// Identifies the configured namespace authority and immutable publication origin.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionNamespaceOwner {
    /// Names the authority whose control must be independently authenticated.
    pub authority: Id,
    /// Binds the published namespace authorization; the reference is not proof.
    pub publication_origin: ContentRef,
}

impl Validate for ExtensionNamespaceOwner {
    fn validate(&self) -> Result<(), ContractError> {
        self.publication_origin.validate()
    }
}

/// Identifies one exact selected definition independently of a feature-name suffix.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionSelection {
    /// Binds the complete declaration bytes under `cnp.blob.v1`.
    pub declaration: ContentRef,
    /// Names the exact owner-controlled semantic identifier.
    pub identifier: Id,
    /// Selects the exact published version, including prerelease/build identity.
    pub semantic_version: SemanticVersion,
    /// Equals the referenced schema definition's exact `cnp.blob.v1` content hash.
    pub schema_digest: HashRef,
}

impl Validate for ExtensionSelection {
    fn validate(&self) -> Result<(), ContractError> {
        self.declaration.validate()?;
        self.semantic_version.validate()?;
        self.schema_digest.validate()?;
        if self.schema_digest.domain != "cnp.blob.v1" {
            return Err(invalid(
                "schema_digest",
                "expected exact schema content identity",
            ));
        }
        validate_extension_identifier(&self.identifier)
    }
}

/// Names an exact core or extension contract required by another extension.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExtensionDependency {
    /// Requires an independently authenticated published core contract.
    Core {
        /// Names the exact reserved core contract.
        identifier: Id,
        /// Selects its exact positive contract edition.
        #[serde(deserialize_with = "crate::deserialize_version")]
        version: Version,
        /// Binds the complete core semantic definition.
        definition: ContentRef,
    },
    /// Requires another exact installed extension definition.
    Extension {
        /// Selects the complete dependency rather than a compatible version range.
        selection: ExtensionSelection,
    },
}

impl ExtensionDependency {
    /// Borrows the exact core or extension identifier for canonical set ordering.
    pub fn identifier(&self) -> &Id {
        match self {
            Self::Core { identifier, .. } => identifier,
            Self::Extension { selection } => &selection.identifier,
        }
    }
}

impl Validate for ExtensionDependency {
    fn validate(&self) -> Result<(), ContractError> {
        match self {
            Self::Core {
                version,
                definition,
                ..
            } => {
                if *version == 0 {
                    return Err(invalid(
                        "core.version",
                        "expected positive exact contract edition",
                    ));
                }
                definition.validate()
            }
            Self::Extension { selection } => selection.validate(),
        }
    }
}

/// Identifies a containing record whose extension semantics require their own handler.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionLocation {
    /// Contains a complete logical node descriptor.
    NodeDescriptor,
    /// Contains a directed port descriptor.
    PortDescriptor,
    /// Contains one directed lane descriptor.
    LaneDescriptor,
    /// Contains a referenced schema identity.
    SchemaRef,
    /// Contains a selected or advertised operation facet.
    FacetSelection,
    /// Contains an operating-mode and timing contract.
    OperatingContract,
    /// Contains a capability profile.
    CapabilityProfile,
    /// Contains a guarantee profile.
    GuaranteeProfile,
    /// Contains an implementation artifact identity.
    ArtifactIdentity,
    /// Contains the complete implementation identity.
    ImplementationIdentity,
    /// Contains durable execution compatibility.
    BindingCompatibility,
    /// Contains an operational binding wrapper.
    NodeBinding,
    /// Contains operational native authority.
    LiveAuthority,
    /// Contains the complete immutable world.
    WorldBinding,
    /// Contains a world or owner reference to a node binding.
    NodeBindingRef,
    /// Contains complete owner bindings.
    OwnerBinding,
    /// Contains a connection descriptor.
    ConnectionDescriptor,
    /// Contains a provider control envelope.
    Envelope,
    /// Contains arguments of an explicitly selected operation.
    MethodArguments,
    /// Contains an explicitly selected operation's result.
    MethodResult,
    /// Contains an explicitly selected error contract.
    Error,
    /// Contains a public event and its causal identity.
    Event,
    /// Contains an immutable input batch.
    InputBatch,
    /// Contains an input admission authorization.
    InputAuthorization,
    /// Contains an observation batch.
    ObservationBatch,
    /// Contains a complete pending inventory.
    PendingInventory,
    /// Contains one retained pending obligation.
    PendingEntry,
    /// Contains a native stop receipt.
    StopReceipt,
    /// Contains a qualified producer port bound.
    PortBound,
    /// Contains a complete activation manifest.
    ActivationManifest,
    /// Contains one original prepared owner receipt.
    PreparedOwner,
    /// Contains an operation control receipt.
    ControlReceipt,
    /// Contains an original input batch's custody record.
    InputCustodyRecord,
    /// Contains an actual closed execution/publication gate record.
    ClosedGateRecord,
    /// Contains actual preparation readiness before activation.
    ActivationReadyRecord,
    /// Contains an actual unchanged-cut native observation.
    UnchangedCutRecord,
    /// Contains actual cleanup and retained-effect disposition.
    CleanupRecord,
    /// Contains an exact installed admission decision record.
    AdmissionRecord,
    /// Contains a complete capture manifest.
    CaptureManifest,
    /// Contains one owner's captured state.
    CapturedOwner,
    /// Contains a node realization/profile manifest.
    NodeManifest,
    /// Contains a provider installation manifest.
    ProviderManifest,
    /// Contains actual realization selections.
    RealizationManifest,
    /// Contains negotiated finite resource allowances.
    ResourceLimits,
}

/// Restricts one containing location independently of implementation qualification.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionApplicability {
    /// Names the exact containing record kind.
    pub location: ExtensionLocation,
    /// Restricts operation kinds for method-scoped use; empty adds no operation.
    pub operation_kinds: IdSet,
    /// Restricts the lane/event direction when applicable.
    #[serde(deserialize_with = "required_nullable")]
    pub direction: Option<Direction>,
    /// Restricts logical roles; empty delegates restrictions to the installed handler.
    pub roles: IdSet,
    /// Restricts actual modes in exact-before-quantized order.
    pub modes: Vec<OperatingMode>,
    /// Restricts selected facets without advertising additional facet support.
    pub facets: IdSet,
    /// Restricts exact port identifiers when applicable.
    pub ports: IdSet,
    /// Restricts exact lane identifiers when applicable.
    pub lanes: IdSet,
}

impl Validate for ExtensionApplicability {
    fn validate(&self) -> Result<(), ContractError> {
        for (field, ids) in [
            ("operation_kinds", &self.operation_kinds),
            ("roles", &self.roles),
            ("facets", &self.facets),
            ("ports", &self.ports),
            ("lanes", &self.lanes),
        ] {
            validate_ids(ids, field)?;
        }
        if self.modes.len() > 2
            || self
                .modes
                .windows(2)
                .any(|pair| matches!(pair, [OperatingMode::Quantized, _]) || pair[0] == pair[1])
        {
            return Err(invalid(
                "modes",
                "expected unique exact-before-quantized modes",
            ));
        }
        Ok(())
    }
}

/// Defines explicit finite extension allowances; zero provides no allowance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionLimits {
    /// Bounds one corresponding message or extension parameter body.
    pub maximum_message_bytes: U64,
    /// Bounds simultaneously retained objects.
    pub maximum_objects: U64,
    /// Bounds total receiving and retained allocation.
    pub maximum_allocation_bytes: U64,
    /// Bounds retained modeled events.
    pub maximum_pending_events: U64,
    /// Bounds retained original operations and retries.
    pub maximum_operations: U64,
}

/// Publishes the complete independently implementable contract of one extension.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionDeclaration {
    /// Selects the closed declaration format, independently of semantic version.
    #[serde(deserialize_with = "crate::deserialize_version")]
    pub schema_version: Version,
    /// Names the exact owner-controlled semantic namespace.
    pub identifier: Id,
    /// Declares the namespace authority; host trust must authenticate it.
    pub owner: ExtensionNamespaceOwner,
    /// Selects the exact published Semantic Version.
    pub semantic_version: SemanticVersion,
    /// Identifies the complete installed parameter schema.
    pub schema: SchemaRef,
    /// Equals `schema.definition.hash`, not the hash of the schema-ref wrapper.
    pub schema_digest: HashRef,
    /// Binds the complete independently implementable specification.
    pub specification: ContentRef,
    /// Enumerates the exact complete dependency contracts in identifier order.
    pub dependencies: Vec<ExtensionDependency>,
    /// Names negotiated requirements without implying those features are available.
    pub required_features: IdSet,
    /// Enumerates one exact applicability clause per containing location.
    pub applicability: Vec<ExtensionApplicability>,
    /// Binds all timing, resolution, and causal-boundary obligations.
    pub timing_effects: ContentRef,
    /// Binds all state, ownership, preservation, and compatibility obligations.
    pub state_effects: ContentRef,
    /// Binds refusal, uncertain effects, retry, cancellation, and disposition.
    pub error_behavior: ContentRef,
    /// Defines finite receiving and retained-state allowances.
    pub limits: ExtensionLimits,
    /// Binds positive/negative qualification cases and their evidence scope.
    pub conformance: ContentRef,
}

impl Validate for ExtensionDeclaration {
    fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != 1 {
            return Err(invalid(
                "schema_version",
                "expected extension declaration edition 1",
            ));
        }
        validate_extension_identifier(&self.identifier)?;
        self.owner.validate()?;
        self.semantic_version.validate()?;
        self.schema.validate()?;
        self.schema_digest.validate()?;
        if self.schema_digest != self.schema.definition.hash || !self.schema.extensions.is_empty() {
            return Err(invalid(
                "schema_digest",
                "expected closed exact schema definition identity",
            ));
        }
        for reference in [
            &self.specification,
            &self.timing_effects,
            &self.state_effects,
            &self.error_behavior,
            &self.conformance,
        ] {
            reference.validate()?;
        }
        validate_sorted(
            &self.dependencies,
            |dependency| dependency.identifier().clone(),
            "dependencies",
        )?;
        for dependency in &self.dependencies {
            dependency.validate()?;
            if dependency.identifier() == &self.identifier {
                return Err(invalid("dependencies", "extension cannot depend on itself"));
            }
        }
        validate_ids(&self.required_features, "required_features")?;
        validate_sorted(&self.applicability, |scope| scope.location, "applicability")?;
        if self.applicability.is_empty() {
            return Err(invalid(
                "applicability",
                "expected at least one declared location",
            ));
        }
        for applicability in &self.applicability {
            applicability.validate()?;
        }
        Ok(())
    }
}

/// Binds exact selected definition and parameters inside an identity-bearing map.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionUse {
    /// Selects exact declaration/version/schema identities without implicit upgrades.
    pub selection: ExtensionSelection,
    /// Carries parameters checked against the actual installed schema and semantics.
    pub parameters: serde_json::Value,
}

impl Validate for ExtensionUse {
    fn validate(&self) -> Result<(), ContractError> {
        self.selection.validate()
    }
}

fn validate_extension_identifier(identifier: &Id) -> Result<(), ContractError> {
    let spelling = identifier.as_str();
    if !spelling.contains(['/', ':', '.']) || spelling.ends_with(['/', ':', '.']) {
        return Err(invalid(
            "identifier",
            "expected owner-controlled namespaced identifier",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    // Contract regressions deliberately panic when canonical identities change.
    // crucible-lint: allow panic-shortcut -- Canonical extension identity regressions deliberately panic when an expected contract invariant changes.
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn version(prerelease: Option<&str>, build: Option<&str>) -> SemanticVersion {
        SemanticVersion {
            major: U64::new(1),
            minor: U64::new(2),
            patch: U64::new(3),
            prerelease: prerelease.map(str::to_owned),
            build: build.map(str::to_owned),
        }
    }

    #[test]
    fn exact_semver_preserves_prerelease_and_build_identity() {
        let first = version(Some("rc.1"), Some("platform.001"));
        let second = version(Some("rc.1"), Some("platform.002"));
        first.validate().unwrap();
        second.validate().unwrap();

        let bytes = serde_json::to_vec(&first).unwrap();
        let decoded: SemanticVersion = canonical::decode(&bytes, 4096).unwrap();

        assert_eq!(decoded, first);
        assert_ne!(first, second);
        assert_ne!(
            canonical::json_hash("cnp.extension-version.v1", &first).unwrap(),
            canonical::json_hash("cnp.extension-version.v1", &second).unwrap()
        );
    }

    #[test]
    fn invalid_semver_identifiers_refuse_instead_of_normalizing() {
        for suffix in ["", "01", "rc..1", "rc_1", "rc/1", "é", "rc."] {
            assert!(version(Some(suffix), None).validate().is_err(), "{suffix}");
        }
        assert!(version(Some(&"r".repeat(129)), None).validate().is_err());
        assert!(version(None, Some("001")).validate().is_ok());
        assert!(version(Some("01-rc"), None).validate().is_ok());
    }

    #[test]
    fn required_nullable_version_fields_do_not_accept_omission() {
        let missing = br#"{"major":"1","minor":"0","patch":"0"}"#;
        assert!(canonical::decode::<SemanticVersion>(missing, 4096).is_err());
        let unknown = br#"{"major":"1","minor":"0","patch":"0","prerelease":null,"build":null,"compatible":true}"#;
        assert!(canonical::decode::<SemanticVersion>(unknown, 4096).is_err());
    }

    #[test]
    fn schema_digest_selects_exact_blob_not_schema_wrapper_identity() {
        let reference =
            canonical::content_ref(b"complete bounded model schema", "text/plain").unwrap();
        let mut selection = ExtensionSelection {
            declaration: reference.clone(),
            identifier: Id::new("vendor/extension").unwrap(),
            semantic_version: version(None, None),
            schema_digest: reference.hash,
        };
        selection.validate().unwrap();
        selection.identifier = Id::new("org.vendor.extension").unwrap();
        selection.validate().unwrap();

        selection.schema_digest =
            canonical::json_hash("cnp.schema-ref.v1", &selection.declaration).unwrap();
        assert!(selection.validate().is_err());
        selection.identifier = Id::new("unnamespaced").unwrap();
        assert!(selection.validate().is_err());
    }
}
