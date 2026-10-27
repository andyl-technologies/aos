//! Quotes and retains the exact original Oracle inputs before any graph work.

use super::*;
use crate::node_qualification::packet_collection::connected::{
    PacketConnectedCase, PacketConnectedCaseKind, PacketConnectedGrant,
};

use crucible_node_format::{Bytes, Id};
use std::mem::size_of;

// These are declarations initially NotExecuted; no case/result/Accepted receipt
// is constructed here. Every later witness still requires its original oracle.
const CASES: [(&str, PacketConnectedCaseKind, usize, Option<usize>); 12] = [
    (
        "packet-connected-stage",
        PacketConnectedCaseKind::Stage,
        1,
        Some(6),
    ),
    (
        "packet-connected-input-ack",
        PacketConnectedCaseKind::InputAcknowledgement,
        1,
        None,
    ),
    (
        "packet-connected-commit",
        PacketConnectedCaseKind::Commit,
        1,
        Some(6),
    ),
    (
        "packet-connected-delivery",
        PacketConnectedCaseKind::Delivery,
        1,
        Some(6),
    ),
    (
        "packet-connected-reaction",
        PacketConnectedCaseKind::Reaction,
        1,
        Some(7),
    ),
    (
        "packet-connected-publication",
        PacketConnectedCaseKind::Publication,
        1,
        Some(8),
    ),
    (
        "packet-connected-before-retirement",
        PacketConnectedCaseKind::BeforeRetirement,
        1,
        None,
    ),
    (
        "packet-connected-after-retirement",
        PacketConnectedCaseKind::AfterRetirement,
        1,
        None,
    ),
    (
        "packet-connected-slow-producer",
        PacketConnectedCaseKind::SlowProducerRefusal,
        1,
        None,
    ),
    (
        "packet-connected-zero-delay",
        PacketConnectedCaseKind::ZeroDelayClosure,
        1,
        Some(8),
    ),
    (
        "packet-connected-positive-delay",
        PacketConnectedCaseKind::PositiveDelayCoordinate,
        2,
        Some(11),
    ),
    (
        "packet-connected-durable-root",
        PacketConnectedCaseKind::DurableRoot,
        0,
        Some(3),
    ),
];

pub(super) fn charge_programme(
    programme: &PacketConnectedSourceProgram,
    c: &mut Counter,
) -> Result<(), RuntimeError> {
    match programme {
        PacketConnectedSourceProgram::Producer { program } => {
            let crucible_node_transport::reference_packet::PacketProgramDefinition {
                schema,
                events,
            } = program;
            c.charge(schema).map_err(storage_error)?;
            c.add(
                events
                    .capacity()
                    .checked_mul(size_of::<
                        crucible_node_transport::reference_packet::PacketEvent,
                    >())
                    .ok_or(RuntimeError::ResourceLimit)?,
            )
            .map_err(storage_error)?;
            for event in events {
                let crucible_node_transport::reference_packet::PacketEvent {
                    id,
                    evaluation: _,
                    completion: _,
                    payload,
                } = event;
                c.charge(id).map_err(storage_error)?;
                c.charge(payload).map_err(storage_error)?;
            }
        }
        PacketConnectedSourceProgram::Reactive { program } => {
            let crucible_node_transport::reference_packet::connected::PacketConnectedDefinition {
                schema,
                connections,
                output,
            } = program;
            c.charge(schema).map_err(storage_error)?;
            c.add(
                connections
                    .capacity()
                    .checked_mul(size_of::<
                        crucible_node_transport::reference_packet::connected::PacketInputConnection,
                    >())
                    .ok_or(RuntimeError::ResourceLimit)?,
            )
            .map_err(storage_error)?;
            for connection in connections {
                let crucible_node_transport::reference_packet::connected::PacketInputConnection {
                    id,
                    policy,
                    producer,
                    consumer,
                    delay_ps: _,
                } = connection;
                c.charge(id).map_err(storage_error)?;
                c.charge(policy).map_err(storage_error)?;
                c.charge(producer).map_err(storage_error)?;
                c.charge(consumer).map_err(storage_error)?;
            }
            c.charge(output).map_err(storage_error)?;
        }
    }
    Ok(())
}

pub(super) fn quote(
    held: &PacketCompleteReportStartupHolder,
    max: usize,
) -> Result<usize, RuntimeError> {
    let bootstrap = held
        .runtime_owners
        .try_borrow()
        .map_err(|_| RuntimeError::OwnerBusy)?
        .capture_bootstrap
        .unwrap_or(super::super::super::super::execution::schedule::Bootstrap::InitialEmpty);
    let mut c = Counter::new(max);
    let bytes = held
        .authority
        .graph_policy
        .original_runtime_content_data()
        .get(&held.authority.world().scenario_ref)
        .ok_or(RuntimeError::OwnerUnavailable)?;
    let (typed, parser, canonical) =
        InstalledConformancePlan::original_runtime_requirements_decode_storage_data(bytes, max)?;
    c.add(typed).map_err(storage_error)?;
    c.add(parser).map_err(storage_error)?;
    c.add(canonical).map_err(storage_error)?;
    c.add(132 + 4096).map_err(storage_error)?;
    for launch in &held.authority.original_launches {
        charge_programme(&launch.program, &mut c)?;
        c.charge(&launch.effects).map_err(storage_error)?;
    }
    // New shared allocations move these exact existing payloads. Their nested
    // backing stays in the current holder row and is never copied/refunded.
    c.add(
        super::super::super::super::retained::shared_requested_storage(
            size_of::<PacketCompleteEffectReceiverReader>(),
            std::mem::align_of::<PacketCompleteEffectReceiverReader>(),
        )
        .map_err(storage_error)?,
    )
    .map_err(storage_error)?;
    c.add(
        super::super::super::super::retained::shared_requested_storage(
            size_of::<PacketWorldHostSupervisor>(),
            std::mem::align_of::<PacketWorldHostSupervisor>(),
        )
        .map_err(storage_error)?,
    )
    .map_err(storage_error)?;
    c.add(13 * size_of::<PacketConnectedGrant>() + 12 * size_of::<PacketConnectedCase>())
        .map_err(storage_error)?;
    for source in &held.authority.roster.sources {
        c.charge(&source.installation().descriptor.id)
            .map_err(storage_error)?;
    }
    for n in 0..13 {
        let (member, id, _) = bootstrap.row(n).ok_or(RuntimeError::UnsupportedFacet)?;
        c.charge(
            &held.authority.roster.sources[member]
                .installation()
                .descriptor
                .id,
        )
        .map_err(storage_error)?;
        c.add(id.len()).map_err(storage_error)?;
    }
    for (id, _, member, operation) in CASES {
        c.add(id.len()).map_err(storage_error)?;
        c.charge(
            &held.authority.roster.sources[member]
                .installation()
                .descriptor
                .id,
        )
        .map_err(storage_error)?;
        if let Some(operation) = operation {
            let (_, id, _) = bootstrap
                .row(operation)
                .ok_or(RuntimeError::UnsupportedFacet)?;
            c.add(id.len()).map_err(storage_error)?;
        }
    }
    Ok(c.bytes())
}

pub(super) fn construct(
    held: &PacketCompleteReportStartupHolder,
    member: &CompleteOriginalRuntimeConstructionMember,
) -> Result<(), RuntimeError> {
    // All corresponding roots are retained before any later validator callback.
    held.receiver_reader.share_original(member)?;
    let scene = held.runtime_construction_owner_data()?;
    scene.share_supervisor(member)?;
    drop(scene);
    let mut owners = held
        .runtime_owners
        .try_borrow_mut()
        .map_err(|_| RuntimeError::OwnerBusy)?;
    let bytes = held
        .authority
        .graph_policy
        .original_runtime_content_data()
        .get(&held.authority.world().scenario_ref)
        .ok_or(RuntimeError::OwnerUnavailable)?;
    let value = crucible_node_format::canonical::parse_json(bytes, bytes.len())
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    owners.requirements =
        Some(serde_json::from_value(value).map_err(|_| RuntimeError::InvalidReceipt)?);
    for i in 0..3 {
        owners.programmes[i] = Some(match &held.authority.original_launches[i].program {
            PacketConnectedSourceProgram::Producer { program } => {
                PacketConnectedSourceProgram::Producer {
                    program: program.clone(),
                }
            }
            PacketConnectedSourceProgram::Reactive { program } => {
                PacketConnectedSourceProgram::Reactive {
                    program: program.clone(),
                }
            }
        });
        owners.paths[i] = Some(held.authority.original_launches[i].effects.clone());
    }
    let schedule = PacketConnectedSchedule {
        nodes: std::array::from_fn(|i| {
            held.authority.roster.sources[i]
                .installation()
                .descriptor
                .id
                .clone()
        }),
        grants: Vec::new(),
        cases: Vec::new(),
    };
    // Install the growing owner before either fallible reservation. Later
    // failures preserve its exact capacities/IDs in this fixed holder slot.
    owners.schedule = Some(schedule);
    let bootstrap = owners
        .capture_bootstrap
        .unwrap_or(super::super::super::super::execution::schedule::Bootstrap::InitialEmpty);
    let schedule = owners
        .schedule
        .as_mut()
        .ok_or(RuntimeError::OwnerUnavailable)?;
    schedule
        .grants
        .try_reserve_exact(13)
        .map_err(|_| RuntimeError::ResourceLimit)?;
    schedule
        .cases
        .try_reserve_exact(12)
        .map_err(|_| RuntimeError::ResourceLimit)?;
    if schedule.grants.capacity() != 13 || schedule.cases.capacity() != 12 {
        return Err(RuntimeError::ResourceLimit);
    }

    for n in 0..13 {
        let (member, id, request) = bootstrap.row(n).ok_or(RuntimeError::UnsupportedFacet)?;
        schedule.grants.push(PacketConnectedGrant {
            node: schedule.nodes[member].clone(),
            operation: Id::new(id).map_err(|_| RuntimeError::UnsupportedFacet)?,
            request,
        });
    }
    for (id, kind, member, operation) in CASES {
        schedule.cases.push(PacketConnectedCase {
            id: id.to_owned(),
            kind,
            node: schedule.nodes[member].clone(),
            operation: operation.map(|index| schedule.grants[index].operation.clone()),
        });
    }
    Ok(())
}
