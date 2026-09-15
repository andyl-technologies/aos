//! Shared semantic fixtures for inspection frontend tests.

use std::collections::BTreeMap;
use std::num::NonZeroU32;

use aos_ability_model::{
    AggregationContract, AggregationScope, ArtifactReference, InterfaceDescriptor,
    InterfaceDocument, InterfaceName, LifecycleSemantics, LocalKey, ProviderImplementation,
    RequiredFeature, ValueSchema,
};
use aos_contract::Sha256Digest;
use aos_doc_model::{AbilityExportReference, PackageAbilityReference};

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

/// Builds the small semantic package reference shared by inspection tests.
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
                stable_resource_identity: true,
                releases_ephemeral_on_disable: true,
                retains_persistent_by_default: false,
                persistent_delete_method: None,
            },
            aggregation,
            guarantees: Vec::new(),
        },
    };
    let interface_key = interface.interface_key().expect("interface key");
    let implementation = ProviderImplementation {
        name: local_key("service"),
        description: "Implements the shared inspection test interface.".to_string(),
        interface: interface_key.clone(),
        guarantees: Vec::new(),
        artifact: ArtifactReference {
            content: Sha256Digest::of_bytes(b"provider-content"),
            store_path: "/nix/store/00000000000000000000000000000000-provider".to_string(),
            nar_hash: Sha256Digest::of_bytes(b"provider-nar"),
            closure: Sha256Digest::of_bytes(b"provider-closure"),
        },
        requirements: Vec::new(),
        desired_schema: None,
        provider_module: None,
        handler: None,
        owns_resource_kinds: Vec::new(),
        state_format: None,
    };
    let implementation_key = implementation
        .descriptor_digest()
        .expect("implementation identity");

    PackageAbilityReference {
        schema: aos_doc_model::ABILITY_REFERENCE_SCHEMA.to_string(),
        required_features: vec![RequiredFeature::new("abilities-v1").expect("feature")],
        package: local_key("inspection-fixture"),
        version: "1.0.0".to_string(),
        manifest_sha256: Sha256Digest::of_bytes(b"manifest"),
        package_digest: Sha256Digest::of_bytes(b"package"),
        interfaces: BTreeMap::from([(local_key("service"), interface)]),
        guarantees: BTreeMap::new(),
        option_declarations: Vec::new(),
        implementations: vec![implementation],
        exports: vec![AbilityExportReference {
            name: local_key("service"),
            interface: interface_key,
            implementation: implementation_key,
            requirements: Vec::new(),
        }],
        requirements: Vec::new(),
        handlers: Vec::new(),
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
