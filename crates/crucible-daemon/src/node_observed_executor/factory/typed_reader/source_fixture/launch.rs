//! Rechecks original private launch bytes and complete source/unit projections.

use super::super::{InstalledTypedReaderPackage, TypedReaderProgramme};
use super::{Source, invalid};
use crate::node_qualification::{QualificationUnit, normative_specification};
use crucible_node_contract::{ContentRef, HashRef, ResourceLimits, U64, Validate, canonical};
use crucible_node_provider::{
    ProviderError, conformance::measure_executable, reference_lineage::InputLineageDefinition,
    reference_service::ReferenceNegotiatedLineageReaderLaunchBootstrap,
};
use serde::Serialize;
use std::{fs::File, io::Read};

pub(super) fn prepare(
    package: &InstalledTypedReaderPackage,
    programme: &TypedReaderProgramme,
    plan: &ContentRef,
    resources: &ResourceLimits,
    world: &HashRef,
    index: usize,
    original: &ReferenceNegotiatedLineageReaderLaunchBootstrap,
) -> Result<Source, ProviderError> {
    let peer = programme.peers.get(index).ok_or_else(invalid)?;
    let bootstrap = &original.bootstrap;
    // Charge all private bytes before any clone. This counter does not retain,
    // hash or publish the private admission capability.
    super::super::owning::count_launch(original, 16 * 1024 * 1024)?;
    original.validate()?;
    if original.closed_ingress != (index < 2)
        || bootstrap.node_id != peer.node
        || bootstrap.owner_id != peer.owner
        || bootstrap.authority.incarnation_id != peer.incarnation
        || bootstrap.resource_limits != *resources
        || bootstrap.world_binding_hash != *world
        || bootstrap.world_generation != U64::new(1)
        || bootstrap.authority.owner_generation != U64::new(1)
        || bootstrap.quantum_ps != U64::new(1000)
        || bootstrap.host_budget_ns != U64::new(1_000_000_000)
        || bootstrap.controller_uid.get() != u64::from(rustix::process::geteuid().as_raw())
        || !original.qualification_refs.contains(plan)
    {
        return Err(invalid());
    }
    let definitions = &original.definition_sources;
    let regenerated = InputLineageDefinition::build_negotiated(
        definitions.namespace_publication.clone(),
        definitions.handler.clone(),
        definitions.event.clone(),
        definitions.input.clone(),
        definitions.stop.clone(),
    )?;
    if regenerated.selection() != package.definition().selection()
        || regenerated.declaration() != package.definition().declaration()
        || regenerated.handler() != package.definition().handler()
        || regenerated.objects() != package.definition().objects()
    {
        return Err(invalid());
    }
    let profile = package
        .profile(
            peer.node.clone(),
            peer.owner.clone(),
            bootstrap.quantum_ps,
            bootstrap.host_budget_ns,
            original.closed_ingress,
        )
        .map_err(|_| invalid())?;
    profile.preflight_retention(1024 * 1024)?;
    let (binding, _) =
        profile.bind_qualified(bootstrap.authority.clone(), &original.qualification_refs)?;
    for reference in &original.qualification_refs {
        bootstrap
            .installed_content
            .iter()
            .find(|object| object.reference == *reference)
            .ok_or_else(invalid)?
            .reference
            .verify(
                bootstrap
                    .installed_content
                    .iter()
                    .find(|object| object.reference == *reference)
                    .ok_or_else(invalid)?
                    .bytes
                    .as_slice(),
            )?;
    }
    Ok(Source {
        profile,
        binding: binding.compatibility,
        launch: original.clone(),
        enrollment: std::cell::RefCell::new(None),
        features: std::cell::RefCell::new(None),
        read_handle: std::cell::RefCell::new(None),
    })
}

pub(super) fn unit(
    package: &InstalledTypedReaderPackage,
    programme: &TypedReaderProgramme,
    resources: &ResourceLimits,
) -> Result<QualificationUnit, ProviderError> {
    resources.validate()?;
    if package.identity() != programme.package() {
        return Err(invalid());
    }
    let mut profiles = Vec::new();
    profiles.try_reserve_exact(3).map_err(|_| invalid())?;
    for (index, peer) in programme.peers.iter().enumerate() {
        profiles.push(
            package
                .profile(
                    peer.node.clone(),
                    peer.owner.clone(),
                    U64::new(1000),
                    U64::new(1_000_000_000),
                    index < 2,
                )
                .map_err(|_| invalid())?,
        );
    }
    // Current host executable is independent of the provider's self-described
    // package and fixes this actual collector/adapter revision before launch.
    let executable = measure_executable(std::path::Path::new("/proc/self/exe"))?;
    let mut release = Vec::new();
    File::open("/proc/sys/kernel/osrelease")?
        .take(4097)
        .read_to_end(&mut release)?;
    if release.is_empty() || release.len() > 4096 {
        return Err(invalid());
    }
    Ok(QualificationUnit {
        implementation: object(
            &profiles
                .iter()
                .map(|profile| &profile.implementation)
                .collect::<Vec<_>>(),
        )?,
        realization: object(&(
            profiles
                .iter()
                .map(|profile| {
                    (
                        &profile.configuration_ref,
                        &profile.node_manifest.profile_id,
                        &profile.owner,
                    )
                })
                .collect::<Vec<_>>(),
            resources,
        ))?,
        descriptors: object(
            &profiles
                .iter()
                .map(|profile| &profile.descriptor)
                .collect::<Vec<_>>(),
        )?,
        contracts: object(
            &profiles
                .iter()
                .map(|profile| {
                    (
                        &profile.operating_contract,
                        &profile.capabilities,
                        &profile.guarantees,
                    )
                })
                .collect::<Vec<_>>(),
        )?,
        port_profiles: object(
            &profiles
                .iter()
                .map(|profile| (&profile.node_manifest, &profile.descriptor.ports))
                .collect::<Vec<_>>(),
        )?,
        environment: object(&(std::env::consts::ARCH, release, resources))?,
        harness: executable,
        fixtures: programme.reference().clone(),
        specification: normative_specification().map_err(|_| invalid())?.0,
    })
}

pub(in super::super) fn encode(
    value: &impl Serialize,
    maximum: usize,
) -> Result<Vec<u8>, ProviderError> {
    super::super::programme::count(value, maximum)?;
    let value = serde_json::to_value(value).map_err(crucible_node_contract::ContractError::from)?;
    Ok(canonical::canonical_json(&value)?)
}

fn object(value: &impl Serialize) -> Result<ContentRef, ProviderError> {
    canonical::content_ref(&encode(value, 256 * 1024)?, "application/json").map_err(Into::into)
}

/// Compares complete immutable profile projections without a wire DTO conversion.
pub(super) fn profile_bytes(
    profile: &crucible_node_provider::reference_service::ReferenceProfile,
) -> Result<Vec<u8>, ProviderError> {
    encode(
        &(
            &profile.descriptor,
            &profile.implementation,
            &profile.operating_contract,
            &profile.capabilities,
            &profile.guarantees,
            &profile.owner,
            &profile.node_manifest,
            &profile.provider_manifest,
            &profile.configuration_ref,
            &profile.content_possession_schema,
            &profile.contents,
        ),
        1024 * 1024,
    )
}
