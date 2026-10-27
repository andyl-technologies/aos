//! Reconstructs complete measured unit bodies from original concrete selections.

use super::*;
use crate::node_qualification::{QualificationUnit, normative_specification};
use serde::Serialize;

/// Retains the independently reconstructed unit and its complete original bodies.
pub(super) struct InterpretedUnit {
    /// Binds all measured native and host roles to the complete world.
    pub(super) unit: QualificationUnit,
    /// Retains the full source-selected body inventory used by that unit.
    pub(super) content: BTreeMap<ContentRef, Vec<u8>>,
    /// Retains the current actual kernel identity checked by the caller.
    pub(super) kernel: String,
}

pub(super) fn interpret(
    request: &PacketConnectedCollectionRequest<'_>,
) -> Result<InterpretedUnit, QualificationError> {
    // Bound all retained source-selected records before building canonical copies.
    let selected = request
        .roster
        .sources
        .iter()
        .map(|source| source.installation())
        .collect::<Vec<_>>();
    let host = request.host.selection();
    scope::encoded_size(
        &(
            &selected
                .iter()
                .map(|one| {
                    (
                        &one.provider,
                        &one.descriptor,
                        &one.binding,
                        &one.owner,
                        &one.realize,
                    )
                })
                .collect::<Vec<_>>(),
            host,
            request.world,
            &request.schedule,
        ),
        2 * 1024 * 1024,
    )?;
    let mut bodies = request.content.clone();
    let measured = request.graph_policy.measurements();
    let implementation = retain(
        &mut bodies,
        &(
            selected
                .iter()
                .map(|one| &one.provider.implementation)
                .collect::<Vec<_>>(),
            &host.binding.compatibility.implementation,
            measured,
        ),
    )?;
    let realization = retain(
        &mut bodies,
        &(
            selected
                .iter()
                .map(|one| {
                    (
                        &one.profile,
                        &one.binding.compatibility,
                        &one.capabilities,
                        &one.guarantees,
                        &one.owner,
                        &one.realize.resource_limits,
                    )
                })
                .collect::<Vec<_>>(),
            host,
            request.world,
        ),
    )?;
    let descriptors = retain(
        &mut bodies,
        &(
            selected
                .iter()
                .map(|one| &one.descriptor)
                .collect::<Vec<_>>(),
            &host.descriptor,
        ),
    )?;
    let contracts = retain(
        &mut bodies,
        &(
            selected
                .iter()
                .map(|one| {
                    (
                        &one.binding.compatibility.operating_contract,
                        &one.exact_facet,
                        &one.receipt_schema,
                        one.maximum_operations,
                        one.maximum_result_bytes,
                        one.maximum_authorization_bytes,
                        one.maximum_semantic_bytes,
                    )
                })
                .collect::<Vec<_>>(),
            &host.binding.compatibility.operating_contract,
        ),
    )?;
    let port_profiles = retain(
        &mut bodies,
        &(
            selected
                .iter()
                .map(|one| (&one.descriptor.roles, &one.descriptor.ports))
                .collect::<Vec<_>>(),
            &host.descriptor.roles,
            &host.descriptor.ports,
            &request.world.connections,
        ),
    )?;
    let kernel = super::super::super::fixture::world_fixture_kernel()?;
    let environment = retain(
        &mut bodies,
        &(
            std::env::consts::ARCH,
            std::env::consts::OS,
            &kernel,
            selected
                .iter()
                .map(|one| &one.realize.resource_limits)
                .collect::<Vec<_>>(),
        ),
    )?;
    let harness = retain(
        &mut bodies,
        &measured
            .iter()
            .map(|one| (&one.host, &one.sources))
            .collect::<Vec<_>>(),
    )?;
    let fixtures = retain(
        &mut bodies,
        &(
            request.coordinator,
            &request.schedule,
            request.world,
            request.requirements,
            "actual original native-three/host-one collection; independent input and effect custody remains required; no accepted class",
        ),
    )?;
    let (specification, bytes) = normative_specification()?;
    if retain_bytes(&mut bodies, bytes)? != specification {
        return Err(refused());
    }
    Ok(InterpretedUnit {
        unit: QualificationUnit {
            implementation,
            realization,
            descriptors,
            contracts,
            port_profiles,
            environment,
            harness,
            fixtures,
            specification,
        },
        content: bodies,
        kernel,
    })
}

fn retain(
    bodies: &mut BTreeMap<ContentRef, Vec<u8>>,
    value: &impl Serialize,
) -> Result<ContentRef, QualificationError> {
    scope::encoded_size(value, 1024 * 1024)?;
    retain_bytes(
        bodies,
        canonical::canonical_json(
            &serde_json::to_value(value).map_err(crucible_node_format::ContractError::from)?,
        )?,
    )
}

fn retain_bytes(
    bodies: &mut BTreeMap<ContentRef, Vec<u8>>,
    bytes: Vec<u8>,
) -> Result<ContentRef, QualificationError> {
    if bytes.len() > 1024 * 1024 {
        return Err(refused());
    }
    let reference = canonical::content_ref(&bytes, "application/json")?;
    if let Some(original) = bodies.get(&reference) {
        if original != &bytes {
            return Err(refused());
        }
    } else {
        let extent = bodies.values().try_fold(bytes.len(), |sum, one| {
            sum.checked_add(one.len()).ok_or_else(refused)
        })?;
        if bodies.len() >= 128 || extent > 2 * 1024 * 1024 {
            return Err(refused());
        }
        bodies.insert(reference.clone(), bytes);
    }
    Ok(reference)
}
