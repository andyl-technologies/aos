//! Constructs the actual Oracle/factory/graph and Source-created inactive nodes.

use super::super::super::super::witness::PacketCompleteSharedOracleRequest;
use super::*;
use crucible_engine::{
    node_admission::{
        AdmissionLimits, AdmissionRequest, FixedFourConformanceGraphConstructionInputs,
        admit_original_fixed_four_conformance_graph,
    },
    node_contract::HostSchedulingSource,
};
use std::mem::{align_of, size_of};

pub(super) fn limits() -> AdmissionLimits {
    AdmissionLimits {
        maximum_nodes: 4,
        maximum_owners: 4,
        maximum_state_objects: 8,
        maximum_connections: 2,
        maximum_ports_or_lanes: 4,
        maximum_owner_conflict_pairs: 12,
        maximum_owner_conflict_checks: 128,
        ..AdmissionLimits::default()
    }
}

pub(super) fn quote(
    held: &PacketCompleteReportStartupHolder,
    max: usize,
) -> Result<(usize, usize, usize), RuntimeError> {
    let owners = held
        .runtime_owners
        .try_borrow()
        .map_err(|_| RuntimeError::OwnerBusy)?;
    let scene = held.runtime_construction_owner_data()?;
    let schedule = owners
        .schedule
        .as_ref()
        .ok_or(RuntimeError::OwnerUnavailable)?;
    let host = held.authority.host_source().selection();
    let selected = held
        .authority
        .roster
        .sources
        .each_ref()
        .map(|source| source.installation());
    let requirements = owners
        .requirements
        .as_ref()
        .ok_or(RuntimeError::OwnerUnavailable)?;
    let content = super::content_limits::OriginalCompleteContentLimits::for_holder(held)?;
    let graph = ConformanceGraph::original_fixed_four_construction_storage_data(
        FixedFourConformanceGraphConstructionInputs {
            world: held.authority.world(),
            descriptors: [
                &selected[0].descriptor,
                &selected[1].descriptor,
                &selected[2].descriptor,
                &host.descriptor,
            ],
            bindings: [
                &selected[0].binding,
                &selected[1].binding,
                &selected[2].binding,
                &host.binding,
            ],
            owners: [
                &selected[0].owner,
                &selected[1].owner,
                &selected[2].owner,
                &host.owner,
            ],
            requirements,
            limits: content.admission,
            content: [
                &held.authority.population.bodies,
                held.authority.graph_policy.original_runtime_content_data(),
            ],
        },
        max,
    )?;
    let node = held
        .preparations
        .try_borrow()
        .map_err(|_| RuntimeError::OwnerBusy)?
        .original_runtime_node_quote_data(&held.authority.roster.sources, max)?;
    // These mandatory callbacks can enroll proofs before runtime attachment.
    // Quote from the actual retained Controllers, before moving preparations;
    // no latest-witness parser or Oracle callback runs inside this DATA walk.
    let oracle_observations = if matches!(&held.purpose, StartupHolderPurpose::OriginalScene) {
        held.preparations
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?
            .original_native_oracle_observation_construction_storage_data(
                &held.authority.roster.sources,
                max,
            )?
    } else {
        (0, 0, 0)
    };
    let host = held.runtime_host_node_construction_data(scene.activation()?, max)?;
    let oracle = PacketCompleteNativeOracle::original_shared_construction_storage_data(
        held.authority.witness_plan(),
        schedule.cases.len(),
        max,
    )?;
    let execution = PacketCompleteExecutionScene::original_construction_storage_data(max)?;
    let actor = PacketCompleteExecutionActor::original_construction_storage_data(
        schedule,
        scene.activation()?,
        max,
    )?;
    let mut extra = Counter::new(max);
    // Oracle owns independent typed copies; the input bank stays retained even
    // if installation refuses before returning the new Oracle Rc.
    for program in owners.programmes.iter().flatten() {
        extra.charge(program).map_err(storage_error)?;
    }
    for path in owners.paths.iter().flatten() {
        extra.charge(path).map_err(storage_error)?;
    }
    extra.charge(schedule).map_err(storage_error)?;
    extra
        .add(
            super::super::super::super::retained::shared_requested_storage(
                size_of::<PacketCompleteCaptureFactory>(),
                align_of::<PacketCompleteCaptureFactory>(),
            )
            .map_err(storage_error)?,
        )
        .map_err(storage_error)?;
    if matches!(&held.purpose, StartupHolderPurpose::FreshRestoration(_)) {
        extra
            .add(held.fresh_graph_wrapper_construction_data(max)?)
            .map_err(storage_error)?;
    }
    let retained = [
        graph.retained_requested_bytes(),
        node.0,
        host.0,
        oracle.retained_requested_bytes,
        oracle_observations.0,
        execution.retained_requested_bytes,
        actor.retained_requested_bytes,
        extra.bytes(),
    ]
    .into_iter()
    .try_fold(0usize, |a, b| add(a, b, max))?;
    // Only the closed actual two-event producer has a Bytes serializer. Admit
    // its separate at-most44-byte base64 bank before invoking any DTO visitor.
    let producer = owners.programmes[0]
        .as_ref()
        .ok_or(RuntimeError::OwnerUnavailable)?;
    match producer {
        PacketConnectedSourceProgram::Producer { program }
            if program.events.len() == 2
                && program.events[0].payload.is_none()
                && program.events[1]
                    .payload
                    .as_ref()
                    .is_some_and(|bytes| bytes.as_slice().len() <= 32) => {}
        _ => return Err(RuntimeError::UnsupportedFacet),
    }
    if owners.programmes[1..]
        .iter()
        .any(|program| !matches!(program, Some(PacketConnectedSourceProgram::Reactive { .. })))
    {
        return Err(RuntimeError::UnsupportedFacet);
    }
    // Oracle validation canonicalizes exact real programme/schedule/plan inputs.
    // Each serializer is a known compiled DTO, never a delegated Serialize.
    let mut transient = add(graph.maximum_simultaneous_transient_bytes(), 44, max)?;
    // The Core projector visits the small retained content maps. Measured file
    // leaves are positional reads outside those maps, one returning Vec at a
    // time. Keep their actual largest read independently funded before admission.
    transient = add(transient, content.external_fetch_bytes, max)?;
    for program in owners.programmes.iter().flatten() {
        transient = add(
            transient,
            InstalledConformancePlan::original_runtime_constructor_serialization_storage_data(
                program, max,
            )?,
            max,
        )?;
    }
    transient = add(
        transient,
        InstalledConformancePlan::original_runtime_constructor_serialization_storage_data(
            schedule, max,
        )?,
        max,
    )?;
    transient = add(
        transient,
        InstalledConformancePlan::original_runtime_constructor_serialization_storage_data(
            held.authority.witness_plan(),
            max,
        )?,
        max,
    )?;
    if matches!(&held.purpose, StartupHolderPurpose::OriginalScene) {
        // A refused nonconsuming peek retains its actual reason String beside
        // the existing Source/constructor diagnostics; fixed S is independent.
        transient = add(
            transient,
            crucible_engine::node_adapters::cnp::PacketCompleteEffectReceiverGroup::original_empty_queue_failure_transient_storage_data(),
            max,
        )?;
    }
    transient = add(transient, oracle_observations.1, max)?;
    transient = add(transient, node.1, max)?;
    transient = add(transient, host.1, max)?;
    let scratch = [
        graph.declared_counter_scratch_bytes(),
        node.2,
        host.2,
        oracle.declared_counter_scratch_bytes,
        oracle_observations.2,
        execution.declared_counter_scratch_bytes,
        actor.declared_counter_scratch_bytes,
    ]
    .into_iter()
    .try_fold(0usize, |a, b| add(a, b, max))?;
    Ok((retained, transient, scratch))
}

fn clone_program(program: &PacketConnectedSourceProgram) -> PacketConnectedSourceProgram {
    match program {
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
    }
}

pub(super) fn construct(held: &PacketCompleteReportStartupHolder) -> Result<(), RuntimeError> {
    let mut owners = held
        .runtime_owners
        .try_borrow_mut()
        .map_err(|_| RuntimeError::OwnerBusy)?;
    let content = super::content_limits::OriginalCompleteContentLimits::for_holder(held)?;
    let programmes = std::array::from_fn(|i| owners.programmes[i].as_ref().map(clone_program));
    let [a, b, c] = programmes;
    let paths = std::array::from_fn(|i| owners.paths[i].clone());
    let [pa, pb, pc] = paths;
    let oracle =
        PacketCompleteNativeOracle::install_original_shared(PacketCompleteSharedOracleRequest {
            roster: held.authority.roster.clone(),
            coordinator: held.authority.coordinator(),
            programmes: [
                a.ok_or(RuntimeError::OwnerUnavailable)?,
                b.ok_or(RuntimeError::OwnerUnavailable)?,
                c.ok_or(RuntimeError::OwnerUnavailable)?,
            ],
            receiver_group: Rc::clone(&held.receiver_group),
            receiver_reader: Rc::clone(&*held.receiver_reader.shared_data()?),
            effect_paths: [
                pa.ok_or(RuntimeError::OwnerUnavailable)?,
                pb.ok_or(RuntimeError::OwnerUnavailable)?,
                pc.ok_or(RuntimeError::OwnerUnavailable)?,
            ],
            schedule: owners
                .schedule
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .clone(),
            plan: held.authority.witness_plan(),
            maximum_bytes: 16 * 1024 * 1024,
        })
        .map_err(|_| RuntimeError::ForeignAuthority)?;
    // Retain before any factory/scene callback can refuse or unwind.
    owners.oracle = Some(oracle);
    owners.factory = Some(
        PacketCompleteCaptureFactory::install(
            Rc::clone(&held.authority),
            Rc::clone(&held.plan),
            content.archive,
        )
        .map_err(|_| RuntimeError::ForeignAuthority)?,
    );
    owners.scene = Some(
        PacketCompleteExecutionScene::install(
            Rc::clone(&held.authority),
            Rc::clone(&held.plan),
            Rc::clone(
                owners
                    .oracle
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?,
            ),
        )
        .map_err(|_| RuntimeError::ForeignAuthority)?,
    );
    let scene = held.runtime_construction_owner_data()?;
    owners.actor = Some(
        owners
            .scene
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .reserve_actor_with_original_supervision(
                Rc::clone(&*scene.shared_supervisor()?),
                scene.activation()?,
                scene.limits()?,
                scene.runtime_slot()?,
            )
            .map_err(|_| RuntimeError::ForeignAuthority)?,
    );
    owners
        .descriptors
        .try_reserve_exact(4)
        .map_err(|_| RuntimeError::ResourceLimit)?;
    owners
        .bindings
        .try_reserve_exact(4)
        .map_err(|_| RuntimeError::ResourceLimit)?;
    owners
        .owners
        .try_reserve_exact(4)
        .map_err(|_| RuntimeError::ResourceLimit)?;
    if owners.descriptors.capacity() != 4
        || owners.bindings.capacity() != 4
        || owners.owners.capacity() != 4
    {
        return Err(RuntimeError::ResourceLimit);
    }

    for source in &held.authority.roster.sources {
        let original = source.installation();
        owners.descriptors.push(original.descriptor.clone());
        owners.bindings.push(original.binding.clone());
        owners.owners.push(original.owner.clone());
    }
    let host = held.authority.host_source().selection();
    owners.descriptors.push(host.descriptor.clone());
    owners.bindings.push(host.binding.clone());
    owners.owners.push(host.owner.clone());
    owners.graph = Some(
        admit_original_fixed_four_conformance_graph(
            AdmissionRequest {
                world: held.authority.world(),
                descriptors: &owners.descriptors,
                bindings: &owners.bindings,
                owners: &owners.owners,
                requirements: owners
                    .requirements
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?,
            },
            &held.plan,
            content.admission,
        )
        .map_err(|_| RuntimeError::ForeignAuthority)?,
    );
    let mut preparations = held
        .preparations
        .try_borrow_mut()
        .map_err(|_| RuntimeError::OwnerBusy)?;
    for i in 0..3 {
        let OriginalRuntimeOwners {
            graph,
            nodes,
            node_failures,
            unwinds,
            ..
        } = &mut *owners;
        preparations.admit_original_runtime_node_into(
            i,
            &held.authority.roster.sources[i],
            graph.as_ref().ok_or(RuntimeError::OwnerUnavailable)?,
            &mut nodes[i],
            &mut node_failures[i],
            &mut unwinds[i],
        )?;
    }
    drop(preparations);
    held.prepare_runtime_host_node_into(&mut owners, scene.activation()?)?;
    Ok(())
}
