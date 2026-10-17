//! Projects only the installed historical reader's known typed profile roles.
//!
//! Each body must equal the authenticated original bytes. Executable and runtime
//! identities remain measurement pins: this model never opens or runs those
//! historical images. Schema, configuration and semantic validator bodies remain
//! positive reconstruction dependencies. Unknown content has no implicit leaf.

use crucible_node_contract::{
    ContentRef, ExtensionDependency, FacetSelection, NodeBinding, NodeManifest, canonical,
};
use crucible_node_provider::reference_service::ReferenceProfile;
use serde::{Deserialize, Serialize};

use super::{
    InstalledReaderPackage,
    conditional_capture_records::insert,
    conditional_profile::{ConditionalProfile, encode},
    conditional_source::InspectionError,
};

/// Adds exact source-regenerated roles before any conditional model callback.
pub(super) fn install(
    target: &mut ConditionalProfile,
    profiles: &[ReferenceProfile],
    package: &InstalledReaderPackage,
) -> Result<(), InspectionError> {
    let source = target
        .history
        .originals
        .values()
        .next()
        .ok_or("original activation body absent")?;
    if source.transcript().origin.activation.owners.len() != 3 {
        return Err("original saved activation owner credit differs".into());
    }
    let activation = encode(&source.transcript().origin.activation)?;
    let activation_ref = canonical::content_ref(&activation, "application/json")
        .map_err(InspectionError::from_error)?;
    if target.content.get(&activation_ref) != Some(&activation) {
        return Err("original saved activation body differs from MAC context".into());
    }
    insert(&mut target.construction_rows, activation_ref, Vec::new())
        .map_err(InspectionError::from_error)?;
    context_fragments(target)?;
    super::conditional_installation_rows::install(target, package)?;
    super::conditional_observation_rows::install(target, package)?;
    // The original world commits the ordered node-to-initialization mapping,
    // independently of the three standalone scalar initialization bodies.
    let initialization: Vec<_> = profiles
        .iter()
        .map(|profile| {
            (
                &profile.descriptor.id,
                &profile.descriptor.initialization_ref,
            )
        })
        .collect();
    typed(
        target,
        &initialization,
        profiles
            .iter()
            .map(|profile| profile.descriptor.initialization_ref.clone())
            .collect(),
    )?;

    profile_roles(target, profiles, package, true)?;
    // The reader builder retains its exact unselected launch4 profile bodies.
    // Regeneration checks those original bodies; this grants no old authority.
    // Reserve conservative metadata occurrences before source builder copies.
    if target
        .construction_rows
        .len()
        .checked_add(384)
        .is_none_or(|n| n > 4096)
        || target
            .construction_rows
            .values()
            .try_fold(24_576usize, |n, row| n.checked_add(row.len()))
            .is_none_or(|n| n > 65_536)
    {
        return Err("historical profile-generation credit exhausted".into());
    }
    let mut base_profiles = Vec::new();
    base_profiles
        .try_reserve_exact(3)
        .map_err(InspectionError::from_error)?;
    for profile in profiles {
        base_profiles.push(
            ReferenceProfile::build_public_lineage(
                profile.descriptor.id.clone(),
                profile.owner.id.clone(),
                package.provider().content.clone(),
                package.device().content.clone(),
                crucible_node_contract::U64::new(1000),
                crucible_node_contract::U64::new(1_000_000_000),
                profile.descriptor.id.as_str() == "source",
            )
            .map_err(InspectionError::from_error)?,
        );
    }
    profile_roles(target, &base_profiles, package, false)?;

    // The original full binding's authority/enrollment is authenticated source
    // history. All operational contract bodies remain positive dependency roles.
    let bindings: Vec<NodeBinding> = target.history.bindings.values().cloned().collect();
    for binding in bindings {
        let expected = package
            .definition()
            .regenerated()
            .durable_extensions()
            .map_err(InspectionError::from_error)?;
        if binding.compatibility.extensions != expected {
            return Err("historical binding extension differs from installed selection".into());
        }
        let mut edges = implementation_edges(&binding.compatibility.implementation);
        edges.extend([
            binding.compatibility.profile_ref.clone(),
            binding.compatibility.configuration_ref.clone(),
            binding.compatibility.operating_contract.policy_ref.clone(),
            binding.compatibility.capabilities_ref.clone(),
            binding.compatibility.guarantees_ref.clone(),
        ]);
        edges.extend(facet_edges(
            &binding.compatibility.operating_contract.facets,
            package,
        )?);
        edges.extend(binding.compatibility.qualification_refs.iter().cloned());
        typed(target, &binding, edges)?;
    }
    let definition = package.definition().regenerated();
    let declaration = definition.declaration();
    let mut edges = vec![
        declaration.owner.publication_origin.clone(),
        declaration.schema.definition.clone(),
        declaration.specification.clone(),
        declaration.timing_effects.clone(),
        declaration.state_effects.clone(),
        declaration.error_behavior.clone(),
        declaration.conformance.clone(),
    ];
    for dependency in &declaration.dependencies {
        edges.push(match dependency {
            ExtensionDependency::Core { definition, .. } => definition.clone(),
            ExtensionDependency::Extension { .. } => {
                return Err("historical nested extension refused".into());
            }
        });
    }
    typed(target, declaration, edges)?;
    // The six source-regenerated specification documents are text codecs;
    // the seventh generated body is the declaration with explicit edges above.
    for (reference, bytes) in definition.objects() {
        if reference == &definition.selection().declaration {
            continue;
        }
        if target.content.get(reference) != Some(bytes) {
            return Err("original installed definition text differs".into());
        }
        insert(&mut target.construction_rows, reference.clone(), Vec::new())
            .map_err(InspectionError::from_error)?;
    }
    Ok(())
}

/// Projects the exact original selected or retained predecessor profile edition.
fn profile_roles(
    target: &mut ConditionalProfile,
    profiles: &[ReferenceProfile],
    package: &InstalledReaderPackage,
    selected_reader: bool,
) -> Result<(), InspectionError> {
    for profile in profiles {
        // These compiled scalar capability/limitation documents name no
        // external content. Exact regenerated bytes are the entire role.
        for reference in [
            &profile.capabilities.devices_ref,
            &profile.capabilities.requirements_ref,
            &profile.guarantees.limitations_ref,
        ] {
            original(target, profile, reference, Vec::new())?;
        }
        profile_policies(target, profile)?;
        // The allowed-combinations document embeds these exact source facets;
        // its full configuration/guarantee/installed-definition refs stay positive.
        let combinations = serde_json::json!({
            "schema_version":1,"modes":["quantized"],"devices":["rolling-checksum"],
            "facets":profile.operating_contract.facets,"capture":"none","continuation":"unsupported"
        });
        if encode(&combinations)?
            != profile
                .content(&profile.node_manifest.allowed_combinations_ref)
                .map_err(InspectionError::from_error)?
        {
            return Err("original allowed combinations differs from source constructor".into());
        }
        original(
            target,
            profile,
            &profile.node_manifest.allowed_combinations_ref,
            facet_edges(&profile.operating_contract.facets, package)?,
        )?;
        let mut template_edges = Vec::new();
        for port in &profile.descriptor.ports {
            template_edges.push(port.configuration_ref.clone());
            template_edges.extend(
                port.lanes
                    .iter()
                    .map(|lane| lane.payload_schema.definition.clone()),
            );
        }
        let templates = encode(&profile.descriptor.ports)?;
        if templates
            != profile
                .content(&profile.node_manifest.port_templates_ref)
                .map_err(InspectionError::from_error)?
        {
            return Err("original port templates differ from source descriptor".into());
        }
        original(
            target,
            profile,
            &profile.node_manifest.port_templates_ref,
            template_edges,
        )?;
        let mut edges = facet_edges(&profile.capabilities.facets, package)?;
        edges.extend([
            profile.capabilities.devices_ref.clone(),
            profile.capabilities.requirements_ref.clone(),
        ]);
        typed(target, &profile.capabilities, edges)?;
        typed(
            target,
            &profile.guarantees,
            vec![profile.guarantees.limitations_ref.clone()],
        )?;
        retained_manifest(
            target,
            &profile.node_manifest,
            manifest_edges(&profile.node_manifest, package)?,
        )?;
        if !profile.provider_manifest.extensions.is_empty()
            || !profile.node_manifest.extensions.is_empty()
            || !profile.implementation.extensions.is_empty()
            || !profile.capabilities.extensions.is_empty()
            || !profile.guarantees.extensions.is_empty()
        {
            return Err("unsupported historical wrapper extension".into());
        }
        let mut edges = implementation_edges(&profile.implementation);
        edges.extend(profile.provider_manifest.qualification_refs.iter().cloned());
        for manifest in &profile.provider_manifest.supported_profiles {
            edges.extend(manifest_edges(manifest, package)?);
        }
        retained_manifest(target, &profile.provider_manifest, edges)?;

        // These exact compiled schema/model documents contain scalar format
        // declarations. The historical image identities are never dereferenced.
        for schema in profile
            .implementation
            .formats
            .iter()
            .chain(std::iter::once(&profile.node_manifest.configuration_schema))
            .chain(profile.node_manifest.state_formats.iter())
        {
            original(target, profile, &schema.definition, Vec::new())?;
        }
        let value = canonical::parse_json(
            profile
                .content(&profile.configuration_ref)
                .map_err(InspectionError::from_error)?,
            65_536,
        )
        .map_err(InspectionError::from_error)?;
        let semantics: ContentRef = serde_json::from_value(
            value
                .get("window_semantics_ref")
                .cloned()
                .ok_or("historical window semantics absent")?,
        )
        .map_err(InspectionError::from_error)?;
        let mut configuration_edges = vec![semantics.clone()];
        if selected_reader {
            let selection: crucible_node_contract::ExtensionSelection = serde_json::from_value(
                value
                    .get("input_reader")
                    .cloned()
                    .ok_or("historical reader selection absent")?,
            )
            .map_err(InspectionError::from_error)?;
            let handler: ContentRef = serde_json::from_value(
                value
                    .get("input_reader_handler")
                    .cloned()
                    .ok_or("historical reader handler absent")?,
            )
            .map_err(InspectionError::from_error)?;
            let definition = package.definition().regenerated();
            if &selection != definition.selection() || &handler != definition.handler() {
                return Err(
                    "historical configuration differs from installed reader definition".into(),
                );
            }
            configuration_edges.extend([selection.declaration, handler]);
        }
        original(
            target,
            profile,
            &profile.configuration_ref,
            configuration_edges,
        )?;
        original(target, profile, &semantics, Vec::new())?;
        for definition in &profile.implementation.model_definitions {
            original(target, profile, definition, Vec::new())?;
        }

        let mut edges = implementation_edges(&profile.implementation);
        edges.extend(descriptor_edges(&profile.descriptor));
        edges.extend(facet_edges(&profile.operating_contract.facets, package)?);
        edges.extend(facet_edges(&profile.capabilities.facets, package)?);
        edges.extend([
            profile.operating_contract.policy_ref.clone(),
            profile.capabilities.devices_ref.clone(),
            profile.capabilities.requirements_ref.clone(),
            profile.guarantees.limitations_ref.clone(),
        ]);
        typed(
            target,
            &serde_json::json!({
                "schema_version":1,"descriptor":profile.descriptor,
                "implementation":profile.implementation,"operating_contract":profile.operating_contract,
                "capabilities":profile.capabilities,"guarantees":profile.guarantees,
            }),
            edges,
        )?;
        retained_manifest(
            target,
            &profile.descriptor,
            descriptor_edges(&profile.descriptor),
        )?;
        original(
            target,
            profile,
            &profile.descriptor.initialization_ref,
            Vec::new(),
        )?;
    }

    for profile in profiles {
        let original = target
            .history
            .bindings
            .get(&profile.descriptor.id)
            .ok_or("original binding is absent for owner projection")?;
        if selected_reader {
            let (binding, owner) = profile
                .bind_qualified(
                    original.authority.clone(),
                    &original.compatibility.qualification_refs,
                )
                .map_err(InspectionError::from_error)?;
            if &binding != original {
                return Err("original owner projection changed binding".into());
            }
            typed(
                target,
                &owner,
                vec![
                    canonical::content_ref(&encode(&binding)?, "application/json")
                        .map_err(InspectionError::from_error)?,
                    owner.ownership_ref.clone(),
                ],
            )?;
            self::original(target, profile, &owner.ownership_ref, Vec::new())?;
        }
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct QuantizedPolicy {
    schema_version: u16,
    mode: String,
    quantum_ps: crucible_node_contract::U64,
    phase_ps: crucible_node_contract::U64,
    host_budget_ns: crucible_node_contract::U64,
    window_proof_ref: ContentRef,
}

/// Projects just the known policy's window role, after exact source equality.
fn profile_policies(
    target: &mut ConditionalProfile,
    profile: &ReferenceProfile,
) -> Result<(), InspectionError> {
    let bytes = profile
        .content(&profile.operating_contract.policy_ref)
        .map_err(InspectionError::from_error)?;
    let policy: QuantizedPolicy = serde_json::from_value(
        canonical::parse_json(bytes, 65_536).map_err(InspectionError::from_error)?,
    )
    .map_err(InspectionError::from_error)?;
    if encode(&policy)? != bytes
        || policy.schema_version != 1
        || policy.mode != "quantized"
        || policy.phase_ps.get() != 0
    {
        return Err("original quantized policy codec differs".into());
    }
    original(target, profile, &policy.window_proof_ref, Vec::new())?;
    original(
        target,
        profile,
        &profile.operating_contract.policy_ref,
        vec![policy.window_proof_ref],
    )
}

/// Decodes only the original closed context fragment edition, whose raw bytes
/// and reconstructed original were authenticated by the tape inspector.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextFragmentManifest {
    format: String,
    #[serde(deserialize_with = "crucible_node_contract::deserialize_version")]
    schema_version: u16,
    original: ContentRef,
    chunk_bytes: crucible_node_contract::U64,
    chunks: Vec<ContextFragment>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextFragment {
    offset: crucible_node_contract::U64,
    content: ContentRef,
}

fn context_fragments(target: &mut ConditionalProfile) -> Result<(), InspectionError> {
    use crate::node_observed_executor::factory::transcript::{
        ORIGINAL_CONTEXT_FRAGMENT_MEDIA_TYPE, reconstruct_fixture_context,
    };

    let history = std::rc::Rc::clone(&target.history);
    for source in history.originals.values() {
        let objects = &source.transcript().origin.context;
        for object in objects {
            if object.reference.media_type != ORIGINAL_CONTEXT_FRAGMENT_MEDIA_TYPE {
                continue;
            }
            let value = canonical::parse_json(&object.bytes, 1024 * 1024)
                .map_err(InspectionError::from_error)?;
            let count = value
                .get("chunks")
                .and_then(serde_json::Value::as_array)
                .filter(|chunks| chunks.len() <= 2048)
                .ok_or("original fragment row credit exceeded")?
                .len();
            if target
                .construction_rows
                .len()
                .checked_add(count + 1)
                .is_none_or(|roles| roles > 4096)
            {
                return Err("original fragment aggregate row credit exceeded".into());
            }
            target
                .construction_rows
                .values()
                .try_fold(count + 1, |total, row| {
                    total
                        .checked_add(row.len())
                        .filter(|total| *total <= 65_536)
                        .ok_or("original fragment aggregate edge credit exceeded")
                })?;
            let manifest: ContextFragmentManifest =
                serde_json::from_value(value).map_err(InspectionError::from_error)?;
            if encode(&manifest)? != object.bytes {
                return Err("original fragment manifest encoding differs".into());
            }
            let original = reconstruct_fixture_context(object, objects, 64 * 1024 * 1024)
                .map_err(InspectionError::from_error)?;
            if original.reference != manifest.original
                || target.content.get(&original.reference) != Some(&original.bytes)
                || target.content.get(&object.reference) != Some(&object.bytes)
            {
                return Err("original context reconstruction is not retained exactly".into());
            }
            let mut dependencies = Vec::new();
            dependencies
                .try_reserve_exact(count + 1)
                .map_err(InspectionError::from_error)?;
            dependencies.push(original.reference);
            for chunk in manifest.chunks {
                let body = objects
                    .iter()
                    .find(|body| body.reference == chunk.content)
                    .ok_or("original context chunk disappeared")?;
                if target.content.get(&chunk.content) != Some(&body.bytes) {
                    return Err("original context chunk is not retained exactly".into());
                }
                // Only these verified raw fragments are opaque byte leaves;
                // the reconstructed semantic body retains its own typed row.
                insert(
                    &mut target.construction_rows,
                    chunk.content.clone(),
                    Vec::new(),
                )
                .map_err(InspectionError::from_error)?;
                dependencies.push(chunk.content);
            }
            insert(
                &mut target.construction_rows,
                object.reference.clone(),
                dependencies,
            )
            .map_err(InspectionError::from_error)?;
        }
    }
    Ok(())
}

fn implementation_edges(value: &crucible_node_contract::ImplementationIdentity) -> Vec<ContentRef> {
    // Only artifact/runtime identities are never-open historical measurement
    // pins. Every model and schema body remains a positive validator role.
    value
        .model_definitions
        .iter()
        .cloned()
        .chain(value.formats.iter().map(|schema| schema.definition.clone()))
        .collect()
}

fn descriptor_edges(value: &crucible_node_contract::NodeDescriptor) -> Vec<ContentRef> {
    let mut edges = vec![
        value.model_ref.clone(),
        value.configuration_ref.clone(),
        value.initialization_ref.clone(),
    ];
    for port in &value.ports {
        edges.push(port.configuration_ref.clone());
        edges.extend(
            port.lanes
                .iter()
                .map(|lane| lane.payload_schema.definition.clone()),
        );
    }
    edges
}

fn facet_edges(
    facets: &[FacetSelection],
    package: &InstalledReaderPackage,
) -> Result<Vec<ContentRef>, InspectionError> {
    if facets.len() > 64 {
        return Err("historical facet credit exhausted".into());
    }
    let expected = package
        .definition()
        .regenerated()
        .durable_extensions()
        .map_err(InspectionError::from_error)?;
    let mut edges = Vec::new();
    edges
        .try_reserve_exact(facets.len() * 4)
        .map_err(InspectionError::from_error)?;
    for facet in facets {
        edges.extend([
            facet.configuration_ref.clone(),
            facet.guarantees_ref.clone(),
        ]);
        if !facet.extensions.is_empty() {
            if facet.extensions != expected {
                return Err(
                    "historical facet extension differs from installed exact selection".into(),
                );
            }
            edges.extend([
                package
                    .definition()
                    .regenerated()
                    .selection()
                    .declaration
                    .clone(),
                package.definition().regenerated().handler().clone(),
            ]);
        }
    }
    Ok(edges)
}

fn manifest_edges(
    manifest: &NodeManifest,
    package: &InstalledReaderPackage,
) -> Result<Vec<ContentRef>, InspectionError> {
    let mut edges = facet_edges(&manifest.operation_facets, package)?;
    edges.extend([
        manifest.configuration_schema.definition.clone(),
        manifest.allowed_combinations_ref.clone(),
        manifest.port_templates_ref.clone(),
    ]);
    edges.extend(
        manifest
            .state_formats
            .iter()
            .map(|schema| schema.definition.clone()),
    );
    Ok(edges)
}

/// Installs an advertised manifest only when its exact standalone source body
/// was retained. An unreferenced builder projection creates no object or row;
/// if the closure later reaches that absent body, content lookup still refuses.
fn retained_manifest<T: Serialize>(
    target: &mut ConditionalProfile,
    value: &T,
    dependencies: Vec<ContentRef>,
) -> Result<(), InspectionError> {
    let bytes = encode(value)?;
    let reference =
        canonical::content_ref(&bytes, "application/json").map_err(InspectionError::from_error)?;
    if !target.content.contains_key(&reference) {
        return Ok(());
    }
    typed(target, value, dependencies)
}

fn typed<T: Serialize>(
    target: &mut ConditionalProfile,
    value: &T,
    dependencies: Vec<ContentRef>,
) -> Result<(), InspectionError> {
    let bytes = encode(value)?;
    let reference =
        canonical::content_ref(&bytes, "application/json").map_err(InspectionError::from_error)?;
    if target.content.get(&reference) != Some(&bytes) {
        return Err(format!(
            "typed historical {} body is not retained exactly: {reference:?}",
            std::any::type_name::<T>()
        )
        .into());
    }
    insert(&mut target.construction_rows, reference, dependencies)
        .map_err(InspectionError::from_error)
}

fn original(
    target: &mut ConditionalProfile,
    source: &ReferenceProfile,
    reference: &ContentRef,
    dependencies: Vec<ContentRef>,
) -> Result<(), InspectionError> {
    let bytes = source
        .content(reference)
        .map_err(InspectionError::from_error)?;
    reference
        .verify(bytes)
        .map_err(InspectionError::from_error)?;
    if target.content.get(reference).map(Vec::as_slice) != Some(bytes) {
        return Err(
            format!("original historical body is not retained exactly: {reference:?}").into(),
        );
    }
    insert(
        &mut target.construction_rows,
        reference.clone(),
        dependencies,
    )
    .map_err(InspectionError::from_error)
}
