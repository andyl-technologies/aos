//! Shared semantic fixtures for inspection frontend tests.

use std::collections::BTreeMap;
use std::num::NonZeroU32;

use aos_ability_model::document::PackageSubject;
use aos_ability_model::{
    AggregationContract, AggregationScope, ArtifactReference, ExportDeclaration,
    InterfaceDescriptor, InterfaceDocument, InterfaceName, LifecycleSemantics, LocalKey,
    ModuleLocator, PackageDocument, PackageImplementation, PackageQualification,
    ProviderImplementation, RelativePath, RequiredFeature, RequirementDeclaration,
    RequirementStrength, ValueSchema, VersionedDocument, encode_canonical,
};
use aos_ability_validate::{
    AbilityContractData, CheckedAbilityContract, validate_ability_contract,
};
use aos_contract::Sha256Digest;
use aos_doc_model::{PackageAbilityReference, ability_reference_supported_features};

use crate::{
    GraphQuery, NodeKey, ReferenceGraphSlice, ReferenceInspectionError, ReferenceInspectionInput,
    ReferenceInspectionView,
};

/// Complete generated artifacts used to compare inspection frontends.
pub struct ReferenceInspectionFixture {
    /// Canonical authenticated inspection input bytes.
    pub input: Vec<u8>,
    /// Canonical bounded query bytes.
    pub query: Vec<u8>,
    /// Canonical public graph slice bytes.
    pub slice: Vec<u8>,
    /// Authenticated package reference from which every artifact was derived.
    pub reference: PackageAbilityReference,
}

/// Builds the checked package projection shared by inspection frontend tests.
#[must_use]
pub fn package_reference() -> PackageAbilityReference {
    let aggregation = AggregationContract {
        scope: AggregationScope::ProviderInstance,
        key: local_key("service"),
        controller_group: local_key("service"),
        reject_slot_collisions: true,
        merge_contract: None,
    };
    let interface = InterfaceDocument {
        schema: "aos.ability.interface/v1".to_string(),
        required_features: vec![RequiredFeature::new("abilities-v1").expect("feature")],
        interface: InterfaceDescriptor {
            description: "Describes the shared inspection test interface.".to_string(),
            name: InterfaceName::new("aos.test.service").expect("interface"),
            abi: NonZeroU32::new(1).expect("nonzero ABI"),
            request: ValueSchema::Boolean,
            configuration: None,
            outputs: BTreeMap::new(),
            methods: BTreeMap::new(),
            lifecycle: LifecycleSemantics {
                persistent_delete_method: None,
            },
            aggregation,
            guarantees: Vec::new(),
        },
    };
    let interface_key = interface.interface_key().expect("interface key");
    let package_requirement = requirement("network", &interface_key);
    let implementation_requirement = requirement("service-runtime", &interface_key);
    let artifact = ArtifactReference {
        content: Sha256Digest::of_bytes(b"provider-content"),
        store_path: "/nix/store/00000000000000000000000000000000-provider".to_string(),
        nar_hash: Sha256Digest::of_bytes(b"provider-nar"),
        closure: Sha256Digest::of_bytes(b"provider-closure"),
    };
    let implementation = ProviderImplementation {
        name: local_key("service"),
        description: "Implements the shared inspection test interface.".to_string(),
        interface: interface_key.clone(),
        methods: Vec::new(),
        guarantees: Vec::new(),
        artifact: artifact.clone(),
        requirements: vec![implementation_requirement],
        desired_schema: None,
        composition_schema: None,
        provider_module: Some(ModuleLocator {
            artifact: artifact.clone(),
            path: RelativePath::new("module.nix").expect("module path"),
        }),
        handler: None,
        owns_resource_kinds: Vec::new(),
        state_format: None,
    };
    let implementation_key = implementation
        .descriptor_digest()
        .expect("implementation identity");
    let package = PackageDocument {
        schema: PackageDocument::SCHEMA.to_string(),
        required_features: vec![
            RequiredFeature::new("abilities-v1").expect("feature"),
            RequiredFeature::new(aos_ability_model::FEATURE_ABILITY_EFFECTS_V1)
                .expect("effects feature"),
        ],
        package: PackageSubject {
            name: local_key("inspection-fixture"),
            version: "1.0.0".to_string(),
            payload: artifact.clone(),
            source: artifact.identity(),
        },
        artifacts: vec![artifact.clone()],
        interfaces: BTreeMap::from([(local_key("service"), interface_key.clone())]),
        guarantees: BTreeMap::new(),
        package_module: Some(ModuleLocator {
            artifact,
            path: RelativePath::new("module.nix").expect("module path"),
        }),
        option_declarations: Vec::new(),
        exports: vec![ExportDeclaration {
            name: local_key("service"),
            interface: interface_key,
            implementation_name: local_key("service"),
            implementation: implementation_key,
        }],
        requirements: vec![package_requirement],
        implementation: PackageImplementation {
            providers: vec![implementation],
            handlers: BTreeMap::new(),
        },
        qualification: PackageQualification::default(),
    };
    let manifest = encode_canonical(&package).expect("package manifest");
    let retained = encode_canonical(&interface).expect("retained interface");
    let retained_interfaces = vec![retained];
    let checked = validate_ability_contract(AbilityContractData::PackageSource {
        manifest: &manifest,
        retained_interfaces: &retained_interfaces,
    })
    .expect("checked package contract");
    let CheckedAbilityContract::PackageSource(checked) = checked else {
        panic!("package source validation returned another contract family");
    };
    let reference = PackageAbilityReference::from_checked_contract(&checked)
        .expect("checked documentation projection");
    let supported = ability_reference_supported_features().expect("reference reader features");
    PackageAbilityReference::from_canonical_json(
        &reference.canonical_json().expect("canonical reference"),
        &supported,
    )
    .expect("decoded checked documentation projection")
}

fn requirement(alias: &str, interface: &aos_ability_model::InterfaceKey) -> RequirementDeclaration {
    RequirementDeclaration {
        description: format!("Consumes the {alias} test ability."),
        alias: local_key(alias),
        accepted_interfaces: vec![interface.clone().into()],
        methods: Vec::new(),
        guarantees: Vec::new(),
        strength: RequirementStrength::Required,
        fallback: None,
    }
}

/// Generates canonical input, query, and slice bytes from the shared reference.
///
/// # Errors
///
/// Returns an error when the semantic reference cannot be checked or encoded.
pub fn reference_inspection_fixture() -> Result<ReferenceInspectionFixture, ReferenceInspectionError>
{
    let reference = package_reference();
    let input = ReferenceInspectionInput::new(reference.clone())?;
    let input_bytes = input.canonical_bytes()?;
    let digest = Sha256Digest::of_bytes(&input_bytes);
    let checked = ReferenceInspectionInput::decode(&input_bytes)?.check(Some(digest))?;
    let view = ReferenceInspectionView::from_checked(&checked)?;
    let query = GraphQuery::new([NodeKey::Package(reference.manifest_sha256)], 1, 2);
    let query_bytes = query
        .canonical_bytes()
        .map_err(ReferenceInspectionError::Query)?;
    let slice: ReferenceGraphSlice = view.query(&query)?;

    Ok(ReferenceInspectionFixture {
        input: input_bytes,
        query: query_bytes,
        slice: slice.canonical_bytes()?,
        reference,
    })
}

fn local_key(value: &str) -> LocalKey {
    LocalKey::new(value).expect("valid fixture local key")
}
