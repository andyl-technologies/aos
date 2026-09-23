//! Whole-node hot-fork ownership transfer, rejection, and quarantine regressions.

use super::*;

#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd as _;

#[path = "hot_fork/isolation.rs"]
mod isolation;

trait HotForkHostContinuationTestExt {
    fn template_generation(&self) -> u64;
    fn private_ring_generation(&self) -> u64;
    fn ring_identity(&self) -> crucible_shmem::SetupRegionBackingIdentity;
    fn plugin_endpoint_identity(&self) -> crate::QmpHotForkPluginEndpointIdentity;
    fn shmem_hot_path_mut(&mut self) -> &mut dyn QemuShmemHotPathChannel;
    fn host_io_binding(&self) -> ContentHash;
    fn node_state(&self) -> &QemuHotForkNodeStateContinuation;
    fn console_observation_available(&self) -> bool;
    fn attach_console_observation(
        &mut self,
        child: &mut QemuNode,
        node: NodeId,
    ) -> Result<(), QemuNodeChannelError>;
}

impl HotForkHostContinuationTestExt for QemuHotForkHostContinuation {
    fn template_generation(&self) -> u64 {
        self.endpoint.template_generation()
    }

    fn private_ring_generation(&self) -> u64 {
        self.endpoint.private_ring_generation()
    }

    fn ring_identity(&self) -> crucible_shmem::SetupRegionBackingIdentity {
        self.ring.backing_identity()
    }

    fn plugin_endpoint_identity(&self) -> crate::QmpHotForkPluginEndpointIdentity {
        self.endpoint.identity()
    }

    fn shmem_hot_path_mut(&mut self) -> &mut dyn QemuShmemHotPathChannel {
        self.shmem_hot_path.as_mut()
    }

    fn host_io_binding(&self) -> ContentHash {
        self.host_io_binding
    }

    fn node_state(&self) -> &QemuHotForkNodeStateContinuation {
        &self.node_state
    }

    fn console_observation_available(&self) -> bool {
        self.console_spool.is_some()
    }

    fn attach_console_observation(
        &mut self,
        child: &mut QemuNode,
        node: NodeId,
    ) -> Result<(), QemuNodeChannelError> {
        if child.console_observation.is_some() {
            return Err(QemuNodeChannelError::new(
                "attach hot-fork child console observation",
                "child node already owns a console observation",
            ));
        }
        let spool = self.console_spool.take().ok_or_else(|| {
            QemuNodeChannelError::new(
                "attach hot-fork child console observation",
                "child console observation was already transferred",
            )
        })?;
        child.console_observation = Some(QemuConsoleObservation { node, spool });
        Ok(())
    }
}

trait HotForkChildLaunchTestExt<A> {
    fn process_authority(&self) -> &A;
    fn child_qmp(&self) -> &QemuHotForkChildQmpHostEndpoint;
    fn host_continuation(&self) -> &QemuHotForkHostContinuation;
}

impl<A> HotForkChildLaunchTestExt<A> for QemuHotForkChildLaunch<A> {
    fn process_authority(&self) -> &A {
        &self.process_authority
    }

    fn child_qmp(&self) -> &QemuHotForkChildQmpHostEndpoint {
        &self.child_qmp
    }

    fn host_continuation(&self) -> &QemuHotForkHostContinuation {
        &self.host_continuation
    }
}

#[test]
#[cfg(target_os = "linux")]
fn hot_fork_success_transfers_child_qmp_and_private_host_continuation() -> Result<(), Box<dyn Error>>
{
    let (mut node, log) = sealed_hot_fork_node_with_log(DescriptorScript::Success)?;
    node.last_observed_time = crucible::VirtualTime { ticks: 41 };
    node.next_network_output_sequence = 17;
    node.next_fault_command_sequence = 23;
    node.next_fault_event_sequence = 29;
    let source_process_id = node.process_id();
    let mut process_owner = ScriptedHotForkChildOwner::default();

    let launch = node.fork_prepared_hot_fork_template(&mut process_owner)?;

    assert_eq!(launch.child_process_id(), 321);
    assert_eq!(launch.parent_state().request(), exact_hot_fork_request());
    assert_eq!(
        launch.parent_state().outcome(),
        crate::QmpHotForkOutcome::Forked
    );
    assert_eq!(process_owner.retained.len(), 1);
    let retained_basis = launch.process_authority().basis;
    assert_eq!(retained_basis.source_process_id(), source_process_id);
    assert_eq!(retained_basis.child_process_id(), 321);
    assert_eq!(retained_basis.request(), exact_hot_fork_request());
    assert_eq!(launch.host_continuation().template_generation(), 1);
    assert_eq!(launch.host_continuation().private_ring_generation(), 1);
    assert_ne!(launch.host_continuation().ring_identity().inode(), 0);
    assert_eq!(
        launch.host_continuation().node_state().last_observed_time(),
        crucible::VirtualTime { ticks: 41 }
    );
    assert_eq!(
        launch
            .host_continuation()
            .node_state()
            .next_network_output_sequence(),
        17
    );
    assert_eq!(
        launch
            .host_continuation()
            .node_state()
            .next_fault_command_sequence(),
        23
    );
    assert_eq!(
        launch
            .host_continuation()
            .node_state()
            .next_fault_event_sequence(),
        29
    );
    assert_eq!(node.lifecycle_state(), QemuNodeLifecycleState::Running);
    let calls = recorded(&log);
    assert_eq!(
        calls
            .iter()
            .filter(|call| matches!(call, ChannelCall::QmpHotForkTemplate))
            .count(),
        4
    );
    assert!(calls.contains(&ChannelCall::QmpHotForkChildProcessContract));
    assert!(calls.contains(&ChannelCall::QmpHotFork));
    assert!(node.take_hot_fork_child_qmp_host_endpoint().is_err());
    let (_parent, _process, child_qmp, mut diagnostics, mut continuation) = launch.into_parts();
    assert_eq!(diagnostics.template_generation(), 1);
    let drain = diagnostics.drain_available()?;
    assert_eq!(drain.bytes_read(), 26);
    assert_eq!(drain.total_retained(), 26);
    assert!(!drain.eof());
    assert!(continuation.console_observation_available());
    continuation.attach_console_observation(&mut node, node_id("fork-child"))?;
    assert!(!continuation.console_observation_available());
    assert!(
        continuation
            .attach_console_observation(&mut node, node_id("second-child"))
            .is_err()
    );
    drop(continuation);
    drop(child_qmp);
    node.release_hot_fork_plugin_endpoints()?;
    node.release_hot_fork_child_console()?;
    node.release_hot_fork_child_qmp()?;
    let capture = node.release_hot_fork_child_diagnostics_with_consumer(&mut diagnostics)?;
    assert_eq!(capture.bytes(), b"scripted child diagnostics");
    drop(node.release_hot_fork_private_ring_mapping()?);
    node.shutdown_child()?;
    Ok(())
}

#[test]
#[cfg(target_os = "linux")]
fn hot_fork_rejects_uncommitted_node_state_before_process_creation() -> Result<(), Box<dyn Error>> {
    let (mut node, log) = sealed_hot_fork_node_with_log(DescriptorScript::Success)?;
    node.pending_network_outputs.push(QemuNodeEmittedFrame {
        source: node_id("source"),
        destination: node_id("destination"),
        emit_icount: crucible::Icount { retired: 1 },
        sequence: 0,
        payload: vec![1],
    });
    let mut process_owner = ScriptedHotForkChildOwner::default();

    let error = node
        .fork_prepared_hot_fork_template(&mut process_owner)
        .expect_err("uncommitted node state must reject before process creation");

    assert!(matches!(error, QemuHotForkLaunchError::Rejected { .. }));
    assert!(process_owner.retained.is_empty());
    assert!(!recorded(&log).contains(&ChannelCall::QmpHotFork));
    node.pending_network_outputs.clear();
    node.shutdown_child()?;
    Ok(())
}

#[test]
#[cfg(target_os = "linux")]
fn hot_fork_scheduler_continuation_owns_exact_private_planes() -> Result<(), Box<dyn Error>> {
    let (mut node, _log) = sealed_hot_fork_node_with_log(DescriptorScript::SchedulerContinuation)?;
    let expected_cancellation = node
        .hot_fork_child_process_contract_stage
        .as_ref()
        .ok_or("target process contract stage is absent")?
        .checkpoint_cancellation_eventfd_id()?;
    node.last_observed_time = crucible::VirtualTime { ticks: 73 };
    node.next_network_output_sequence = 31;
    let mut process_owner = ScriptedHotForkChildOwner::default();

    let launch = node.fork_prepared_hot_fork_template(&mut process_owner)?;
    let (_parent, process, child_qmp, mut diagnostics, continuation) = launch.into_parts();
    let scheduler = continuation.into_scheduler_node_continuation(child_qmp)?;

    assert_eq!(scheduler.request(), exact_hot_fork_request());
    assert_eq!(scheduler.template_generation(), 1);
    assert_eq!(scheduler.private_ring_generation(), 1);
    assert_ne!(scheduler.host_io_binding(), ContentHash { bytes: [0; 32] });
    assert_eq!(
        scheduler.node_state().last_observed_time(),
        crucible::VirtualTime { ticks: 73 }
    );
    assert_eq!(scheduler.node_state().next_network_output_sequence(), 31);

    let installed = scheduler.into_qemu_node(
        node_id("child"),
        ScriptedExternalProcessControl {
            basis: process.basis,
        },
        QemuShutdownPolicy::fast_test(),
        QemuAsyncDriverPolicy::fast_test(),
        QemuCrashDetector::new("child"),
    )?;
    assert_eq!(installed.process_id(), 321);
    assert!(!installed.child_reaped());
    assert_eq!(installed.last_observed_time, VirtualTime { ticks: 73 });
    assert_eq!(installed.next_network_output_sequence, 31);
    let installed_cancellation = installed
        .checkpoint_cancellation
        .as_ref()
        .ok_or("installed node omitted checkpoint cancellation")?;
    assert_eq!(
        crate::node::hot_fork_plugin_endpoints::eventfd_id(installed_cancellation.as_raw_fd())?,
        expected_cancellation,
    );
    assert!(installed._hot_fork_scheduler_authority.is_some());
    drop(installed);
    node.release_hot_fork_plugin_endpoints()?;
    node.release_hot_fork_child_console()?;
    node.release_hot_fork_child_qmp()?;
    let _capture = node.release_hot_fork_child_diagnostics_with_consumer(&mut diagnostics)?;
    drop(node.release_hot_fork_private_ring_mapping()?);
    node.shutdown_child()?;
    Ok(())
}

#[test]
#[cfg(target_os = "linux")]
fn hot_fork_derived_request_rejects_a_foreign_qmp_basis_before_fork() -> Result<(), Box<dyn Error>>
{
    let (mut node, log) = sealed_hot_fork_node_with_log(DescriptorScript::RequestBasisMismatch)?;
    let mut process_owner = ScriptedHotForkChildOwner::default();

    let error = node
        .fork_prepared_hot_fork_template(&mut process_owner)
        .expect_err("a QMP template bound to another ring generation must be rejected");

    assert!(matches!(
        error,
        crate::QemuHotForkLaunchError::Rejected { .. }
    ));
    assert!(process_owner.retained.is_empty());
    assert_eq!(node.lifecycle_state(), QemuNodeLifecycleState::Running);
    assert!(!recorded(&log).contains(&ChannelCall::QmpHotFork));
    node.shutdown_child()?;
    Ok(())
}

#[test]
#[cfg(target_os = "linux")]
fn hot_fork_rejects_host_io_clone_failure_before_qmp_or_process_retention()
-> Result<(), Box<dyn Error>> {
    let (mut node, log) = sealed_hot_fork_node_with_log(DescriptorScript::HostIoCloneFailure)?;
    let mut process_owner = ScriptedHotForkChildOwner::default();

    let error = node
        .fork_hot_fork_template(exact_hot_fork_request(), &mut process_owner)
        .expect_err("host-I/O cloning must fail before the fork command");

    assert!(matches!(
        error,
        crate::QemuHotForkLaunchError::Rejected { .. }
    ));
    assert!(process_owner.retained.is_empty());
    assert_eq!(node.lifecycle_state(), QemuNodeLifecycleState::Running);
    let calls = recorded(&log);
    assert!(calls.contains(&ChannelCall::HostHotForkContinuationClone));
    assert!(!calls.contains(&ChannelCall::QmpHotFork));
    node.shutdown_child()?;
    Ok(())
}

#[test]
#[cfg(target_os = "linux")]
fn hot_fork_rejects_a_foreign_private_ring_before_consuming_host_continuation()
-> Result<(), Box<dyn Error>> {
    let mut node = sealed_hot_fork_node(DescriptorScript::Success)?;
    let mut process_owner = ScriptedHotForkChildOwner::default();
    let foreign_ring =
        crate::QmpHotForkRequest::for_test(1, 2, 3, 4, 1, 5, 6, 7, 8, 9, 10, 11, 12, 13, 0);

    let error = node
        .fork_hot_fork_template(foreign_ring, &mut process_owner)
        .expect_err("a foreign private ring must fail before the fork command");
    assert!(matches!(
        error,
        crate::QemuHotForkLaunchError::Rejected { .. }
    ));
    assert!(process_owner.retained.is_empty());
    assert_eq!(node.lifecycle_state(), QemuNodeLifecycleState::Running);

    let foreign_console =
        crate::QmpHotForkRequest::for_test(1, 1, 3, 4, 2, 5, 6, 7, 8, 9, 10, 11, 12, 13, 0);
    let error = node
        .fork_hot_fork_template(foreign_console, &mut process_owner)
        .expect_err("a foreign child console must fail before the fork command");
    assert!(matches!(
        error,
        crate::QemuHotForkLaunchError::Rejected { .. }
    ));
    assert!(process_owner.retained.is_empty());
    assert_eq!(node.lifecycle_state(), QemuNodeLifecycleState::Running);

    let launch = node.fork_hot_fork_template(exact_hot_fork_request(), &mut process_owner)?;
    assert_eq!(launch.host_continuation().private_ring_generation(), 1);
    drop(launch);
    node.shutdown_child()?;
    Ok(())
}

#[test]
#[cfg(target_os = "linux")]
fn hot_fork_explicit_rejection_retains_a_reusable_source_owner() -> Result<(), Box<dyn Error>> {
    let mut node = sealed_hot_fork_node(DescriptorScript::ForkRejected)?;
    let mut process_owner = ScriptedHotForkChildOwner::default();

    let error = node
        .fork_hot_fork_template(exact_hot_fork_request(), &mut process_owner)
        .expect_err("explicit rejection must not produce a child launch");

    assert!(matches!(
        error,
        crate::QemuHotForkLaunchError::Rejected { .. }
    ));
    assert!(process_owner.retained.is_empty());
    assert_eq!(node.lifecycle_state(), QemuNodeLifecycleState::Running);
    let retained = node.take_hot_fork_child_qmp_host_endpoint()?;
    drop(retained);
    node.shutdown_child()?;
    Ok(())
}

#[test]
#[cfg(target_os = "linux")]
fn hot_fork_indeterminate_exchange_quarantines_the_complete_source_owner()
-> Result<(), Box<dyn Error>> {
    let mut node = crate::node::test_support::hot_fork::scripted_hot_fork_source_for_test(
        crate::node::test_support::hot_fork::QemuTestHotForkOutcome::Indeterminate,
    )?;
    node.prepare_hot_fork_child_resources(usize::MAX)?;
    node.install_test_hot_fork_child_process_contract_stage(13, 1)?;
    let mut process_owner = ScriptedHotForkChildOwner::default();

    let error = node
        .fork_hot_fork_template(exact_hot_fork_request(), &mut process_owner)
        .expect_err("indeterminate exchange must not expose a child launch");

    assert!(matches!(
        error,
        crate::QemuHotForkLaunchError::Indeterminate { .. }
    ));
    assert!(process_owner.retained.is_empty());
    assert_eq!(node.lifecycle_state(), QemuNodeLifecycleState::Quarantined);
    assert!(
        node.hot_fork_child_qmp_stage()
            .ok_or("quarantine discarded the child QMP stage")?
            .resource_plan_bound()
    );
    node.shutdown_child()?;
    Ok(())
}

#[test]
#[cfg(target_os = "linux")]
fn hot_fork_parent_disposition_failure_preserves_child_identity_and_quarantines()
-> Result<(), Box<dyn Error>> {
    let mut node = sealed_hot_fork_node(DescriptorScript::ForkParentDispositionFailed)?;
    let mut process_owner = ScriptedHotForkChildOwner::default();

    let error = node
        .fork_hot_fork_template(exact_hot_fork_request(), &mut process_owner)
        .expect_err("failed parent disposition must quarantine the source owner");

    assert!(matches!(
        error,
        crate::QemuHotForkLaunchError::ParentDispositionFailed {
            child_pid: 321,
            parent_status: -1,
        }
    ));
    assert!(process_owner.retained.is_empty());
    assert_eq!(node.lifecycle_state(), QemuNodeLifecycleState::Quarantined);
    node.shutdown_child()?;
    Ok(())
}

#[test]
#[cfg(target_os = "linux")]
fn hot_fork_success_without_a_transferable_endpoint_quarantines_the_source()
-> Result<(), Box<dyn Error>> {
    let mut node = sealed_hot_fork_node(DescriptorScript::Success)?;
    let mut process_owner = ScriptedHotForkChildOwner::default();
    let consumed = node.take_hot_fork_child_qmp_host_endpoint()?;
    drop(consumed);

    let error = node
        .fork_hot_fork_template(exact_hot_fork_request(), &mut process_owner)
        .expect_err("a created child without its endpoint must quarantine the source");

    assert!(matches!(
        error,
        crate::QemuHotForkLaunchError::EndpointTransfer { .. }
    ));
    assert!(process_owner.retained.is_empty());
    assert_eq!(node.lifecycle_state(), QemuNodeLifecycleState::Quarantined);
    node.shutdown_child()?;
    Ok(())
}

#[test]
#[cfg(target_os = "linux")]
fn hot_fork_process_retention_failure_quarantines_before_endpoint_admission()
-> Result<(), Box<dyn Error>> {
    let mut node = sealed_hot_fork_node(DescriptorScript::Success)?;
    let mut process_owner = ScriptedHotForkChildOwner {
        fail: true,
        retained: Vec::new(),
    };

    let error = node
        .fork_hot_fork_template(exact_hot_fork_request(), &mut process_owner)
        .expect_err("an unauthenticated child process must not expose its endpoint");

    assert!(matches!(
        error,
        crate::QemuHotForkLaunchError::ProcessRetention { .. }
    ));
    assert_eq!(process_owner.retained.len(), 1);
    assert_eq!(node.lifecycle_state(), QemuNodeLifecycleState::Quarantined);
    node.shutdown_child()?;
    Ok(())
}

#[test]
#[cfg(target_os = "linux")]
fn hot_fork_child_resources_are_prepared_in_one_authenticated_order() -> Result<(), Box<dyn Error>>
{
    let (setup_identity, host_barrier, image) = held_hot_fork_ring_image()?;
    let barrier = crate::QmpHotForkPluginBarrierState::one_quiescent(
        exact_hot_fork_request().plugin_barrier_generation(),
        host_barrier.ring_count(),
    );
    let log = shared_log();
    let mut node = scripted_hot_fork_capture_node(
        Arc::clone(&log),
        setup_identity,
        setup_identity,
        host_barrier,
        image.clone(),
        [barrier; 8],
        DescriptorScript::Success,
    )?;

    let prepared = node.prepare_hot_fork_child_resources(image.canonical_len()?)?;

    assert_eq!(prepared.template().generation(), 1);
    assert_eq!(
        prepared.template().outcome(),
        crate::QmpHotForkTemplateOutcome::Prepared
    );
    assert!(prepared.template().ready());
    assert_eq!(
        prepared.private_ring().state(),
        crate::QemuHotForkPrivateRingStageState::Installed
    );
    assert_eq!(
        prepared
            .template()
            .resource_stage()
            .private_ring_generation(),
        1
    );
    assert_eq!(prepared.diagnostics().template_generation(), 1);
    assert!(prepared.diagnostics().replacement_plan_bound());
    assert_eq!(prepared.child_qmp().template_generation(), 1);
    assert!(prepared.child_qmp().resource_plan_bound());
    assert_eq!(prepared.child_console().template_generation(), 1);
    assert!(prepared.child_console().resource_plan_bound());
    assert_eq!(prepared.plugin_endpoints().template_generation(), 1);
    assert!(node.hot_fork_child_process_contract_stage().is_none());

    let calls = recorded(&log);
    let first_template = calls
        .iter()
        .position(|call| matches!(call, ChannelCall::QmpHotForkTemplate))
        .ok_or("initial template query was not recorded")?;
    let private_ring = calls
        .iter()
        .position(|call| matches!(call, ChannelCall::QmpHotForkInstallDescriptor(..)))
        .ok_or("private-ring install was not recorded")?;
    let diagnostics = calls
        .iter()
        .position(|call| matches!(call, ChannelCall::QmpHotForkInstallDiagnostics { .. }))
        .ok_or("diagnostics install was not recorded")?;
    let child_qmp = calls
        .iter()
        .position(|call| matches!(call, ChannelCall::QmpHotForkInstallChildQmp { .. }))
        .ok_or("child-QMP install was not recorded")?;
    let child_console = calls
        .iter()
        .position(|call| matches!(call, ChannelCall::QmpHotForkInstallChildConsole { .. }))
        .ok_or("child-console install was not recorded")?;
    let plugin_endpoints = calls
        .iter()
        .position(|call| matches!(call, ChannelCall::QmpHotForkInstallPluginEndpoints { .. }))
        .ok_or("plugin-endpoint install was not recorded")?;
    let final_template = calls
        .iter()
        .rposition(|call| matches!(call, ChannelCall::QmpHotForkTemplate))
        .ok_or("final template query was not recorded")?;
    assert!(
        first_template < private_ring
            && private_ring < diagnostics
            && diagnostics < child_qmp
            && child_qmp < child_console
            && child_console < plugin_endpoints
            && plugin_endpoints < final_template
    );

    node.shutdown_child()?;
    Ok(())
}

#[test]
#[cfg(target_os = "linux")]
fn hot_fork_target_process_contract_is_staged_before_child_creation() -> Result<(), Box<dyn Error>>
{
    let (mut node, log) = prepared_hot_fork_node_with_log(DescriptorScript::Success)?;
    let mut process_owner = ScriptedHotForkTargetOwner {
        contract: unvalidated_hot_fork_process_contract()?,
        retained: Vec::new(),
    };

    let launch =
        node.fork_prepared_hot_fork_template_into(&mut process_owner, |owner| Ok(&owner.contract))?;

    assert_eq!(launch.child_process_id(), 321);
    let calls = recorded(&log);
    let stage = calls
        .iter()
        .position(|call| matches!(call, ChannelCall::QmpHotForkInstallProcessContract))
        .ok_or("process contract stage was not recorded")?;
    let fork = calls
        .iter()
        .position(|call| matches!(call, ChannelCall::QmpHotFork))
        .ok_or("hot fork was not recorded")?;
    assert!(stage < fork);
    assert!(
        node.hot_fork_child_process_contract_stage()
            .is_some_and(|proof| proof.consumed())
    );

    drop(launch);
    node.shutdown_child()?;
    Ok(())
}

#[test]
#[cfg(target_os = "linux")]
fn hot_fork_with_files_stages_the_plan_before_the_contract_and_fork() -> Result<(), Box<dyn Error>>
{
    use std::os::fd::AsFd as _;

    let (mut node, log) = prepared_hot_fork_node_with_log(DescriptorScript::Success)?;
    let mut process_owner = ScriptedHotForkTargetOwner {
        contract: unvalidated_hot_fork_process_contract()?,
        retained: Vec::new(),
    };
    let directory = tempfile::tempdir()?;
    let vmstate = std::fs::File::create(directory.path().join("vmstate.qcow2"))?;
    let vmstate_root = crate::QmpHotForkChildFileRoot::node_name("vmstate")?;
    let destinations = [crate::QemuHotForkChildFileDestination::new(
        &vmstate_root,
        vmstate.as_fd(),
    )];

    let launch = node.fork_prepared_hot_fork_template_with_files_into(
        &mut process_owner,
        |owner| Ok(&owner.contract),
        &destinations,
        1 << 20,
    )?;

    // The plan is bound to QEMU's template generation, consumed exactly once,
    // and staged before the target contract and the fork itself.
    let plan = node
        .hot_fork_child_files_stage()
        .ok_or("child file plan was not retained")?;
    assert!(plan.consumed());
    assert_eq!(plan.template_generation(), 1);
    assert_eq!(
        launch.parent_state().request().child_files_generation(),
        plan.generation()
    );
    let calls = recorded(&log);
    let files = calls
        .iter()
        .position(|call| matches!(call, ChannelCall::QmpHotForkInstallChildFiles))
        .ok_or("child file stage was not recorded")?;
    let contract = calls
        .iter()
        .position(|call| matches!(call, ChannelCall::QmpHotForkInstallProcessContract))
        .ok_or("process contract stage was not recorded")?;
    let fork = calls
        .iter()
        .position(|call| matches!(call, ChannelCall::QmpHotFork))
        .ok_or("hot fork was not recorded")?;
    assert!(files < contract && contract < fork);

    drop(launch);
    node.shutdown_child()?;
    Ok(())
}

#[test]
#[cfg(target_os = "linux")]
fn hot_fork_with_files_explicit_rejection_releases_the_plan() -> Result<(), Box<dyn Error>> {
    use std::os::fd::AsFd as _;

    let (mut node, log) = prepared_hot_fork_node_with_log(DescriptorScript::ForkRejected)?;
    let mut process_owner = ScriptedHotForkTargetOwner {
        contract: unvalidated_hot_fork_process_contract()?,
        retained: Vec::new(),
    };
    let directory = tempfile::tempdir()?;
    let vmstate = std::fs::File::create(directory.path().join("vmstate.qcow2"))?;
    let vmstate_root = crate::QmpHotForkChildFileRoot::node_name("vmstate")?;
    let destinations = [crate::QemuHotForkChildFileDestination::new(
        &vmstate_root,
        vmstate.as_fd(),
    )];

    let error = node
        .fork_prepared_hot_fork_template_with_files_into(
            &mut process_owner,
            |owner| Ok(&owner.contract),
            &destinations,
            1 << 20,
        )
        .expect_err("scripted source must reject before child creation");

    assert!(matches!(
        error,
        crate::QemuHotForkLaunchError::Rejected { .. }
    ));
    assert!(node.hot_fork_child_files_stage().is_none());
    assert!(node.hot_fork_child_process_contract_stage().is_none());
    let calls = recorded(&log);
    let fork = calls
        .iter()
        .position(|call| matches!(call, ChannelCall::QmpHotFork))
        .ok_or("hot fork was not recorded")?;
    let release = calls
        .iter()
        .position(|call| matches!(call, ChannelCall::QmpHotForkReleaseChildFiles))
        .ok_or("child file release was not recorded")?;
    assert!(fork < release);

    node.shutdown_child()?;
    Ok(())
}

#[test]
#[cfg(target_os = "linux")]
fn hot_fork_explicit_rejection_rolls_back_the_target_process_contract() -> Result<(), Box<dyn Error>>
{
    let (mut node, log) = prepared_hot_fork_node_with_log(DescriptorScript::ForkRejected)?;
    let mut process_owner = ScriptedHotForkTargetOwner {
        contract: unvalidated_hot_fork_process_contract()?,
        retained: Vec::new(),
    };

    let error = node
        .fork_prepared_hot_fork_template_into(&mut process_owner, |owner| Ok(&owner.contract))
        .expect_err("scripted source must reject before child creation");

    assert!(matches!(
        error,
        crate::QemuHotForkLaunchError::Rejected { .. }
    ));
    assert!(node.hot_fork_child_process_contract_stage().is_none());
    let calls = recorded(&log);
    let stage = calls
        .iter()
        .position(|call| matches!(call, ChannelCall::QmpHotForkInstallProcessContract))
        .ok_or("process contract stage was not recorded")?;
    let fork = calls
        .iter()
        .position(|call| matches!(call, ChannelCall::QmpHotFork))
        .ok_or("hot fork was not recorded")?;
    let release = calls
        .iter()
        .position(|call| matches!(call, ChannelCall::QmpHotForkReleaseProcessContract))
        .ok_or("process contract rollback was not recorded")?;
    assert!(stage < fork && fork < release);

    node.shutdown_child()?;
    Ok(())
}

#[test]
#[cfg(target_os = "linux")]
fn hot_fork_plugin_endpoint_transfer_failure_retains_and_quarantines_owner()
-> Result<(), Box<dyn Error>> {
    let (setup_identity, host_barrier, image) = held_hot_fork_ring_image()?;
    let barrier = crate::QmpHotForkPluginBarrierState::one_quiescent(13, host_barrier.ring_count());
    let mut node = scripted_hot_fork_capture_node(
        shared_log(),
        setup_identity,
        setup_identity,
        host_barrier,
        image.clone(),
        [barrier; 8],
        DescriptorScript::EndpointInstallFailure,
    )?;
    let capture = node.capture_hot_fork_plugin_ring_image(image.canonical_len()?)?;
    let private = node.materialize_hot_fork_private_ring_mapping(capture)?;
    node.stage_hot_fork_private_ring_mapping(private)?;
    node.stage_hot_fork_child_diagnostics()?;
    node.stage_hot_fork_child_qmp()?;
    node.stage_hot_fork_child_console()?;

    let error = node
        .stage_hot_fork_plugin_endpoints()
        .expect_err("endpoint transfer failure must remain ownership-ambiguous");
    assert!(matches!(
        error,
        crate::QemuHotForkPluginEndpointStageError::TransferUncertain { .. }
    ));
    assert_eq!(node.lifecycle_state(), QemuNodeLifecycleState::Quarantined);
    assert_eq!(
        node.hot_fork_plugin_endpoint_stage()
            .ok_or("ambiguous endpoint owner was not retained")?
            .state(),
        crate::QemuHotForkPluginEndpointStageState::TransferUncertain
    );
    assert!(node.release_hot_fork_plugin_endpoints().is_err());
    node.shutdown_child()?;
    Ok(())
}

#[test]
#[cfg(target_os = "linux")]
fn hot_fork_plugin_endpoint_worker_disposition_mismatch_quarantines_owner()
-> Result<(), Box<dyn Error>> {
    let (setup_identity, host_barrier, image) = held_hot_fork_ring_image()?;
    let barrier = crate::QmpHotForkPluginBarrierState::one_quiescent(14, host_barrier.ring_count());
    let mut node = scripted_hot_fork_capture_node(
        shared_log(),
        setup_identity,
        setup_identity,
        host_barrier,
        image.clone(),
        [barrier; 8],
        DescriptorScript::EndpointDispositionMismatch,
    )?;
    let capture = node.capture_hot_fork_plugin_ring_image(image.canonical_len()?)?;
    let private = node.materialize_hot_fork_private_ring_mapping(capture)?;
    node.stage_hot_fork_private_ring_mapping(private)?;
    node.stage_hot_fork_child_diagnostics()?;
    node.stage_hot_fork_child_qmp()?;
    node.stage_hot_fork_child_console()?;

    let error = node
        .stage_hot_fork_plugin_endpoints()
        .expect_err("foreign worker disposition must remain ownership-ambiguous");
    assert!(matches!(
        error,
        crate::QemuHotForkPluginEndpointStageError::TransferUncertain { .. }
    ));
    assert_eq!(node.lifecycle_state(), QemuNodeLifecycleState::Quarantined);
    assert_eq!(
        node.hot_fork_plugin_endpoint_stage()
            .ok_or("mismatched endpoint owner was not retained")?
            .state(),
        crate::QemuHotForkPluginEndpointStageState::TransferUncertain
    );
    node.shutdown_child()?;
    Ok(())
}

#[test]
#[cfg(target_os = "linux")]
fn hot_fork_private_ring_stage_returns_mapping_before_transfer_on_source_drift()
-> Result<(), Box<dyn Error>> {
    let (setup_identity, host_barrier, image) = held_hot_fork_ring_image()?;
    let barrier = crate::QmpHotForkPluginBarrierState::one_quiescent(13, host_barrier.ring_count());
    let changed = crate::QmpHotForkPluginBarrierState::one_quiescent(
        barrier.generation() + 1,
        host_barrier.ring_count(),
    );
    let mut node = scripted_hot_fork_capture_node(
        shared_log(),
        setup_identity,
        setup_identity,
        host_barrier,
        image.clone(),
        [barrier, barrier, barrier, barrier, changed],
        DescriptorScript::Success,
    )?;
    let capture = node.capture_hot_fork_plugin_ring_image(image.canonical_len()?)?;
    let private = node.materialize_hot_fork_private_ring_mapping(capture)?;
    let identity = private.backing_identity();
    let error = node
        .stage_hot_fork_private_ring_mapping(private)
        .expect_err("source drift must reject before descriptor transfer");
    let returned = error
        .into_untransferred_mapping()
        .ok_or("pre-transfer rejection did not return mapping")?;
    assert_eq!(returned.backing_identity(), identity);
    assert_eq!(node.lifecycle_state(), QemuNodeLifecycleState::Running);
    assert!(node.hot_fork_private_ring_stage().is_none());
    node.shutdown_child()?;
    Ok(())
}

#[test]
#[cfg(target_os = "linux")]
fn hot_fork_child_files_stage_requires_empty_regular_destinations() -> Result<(), Box<dyn Error>> {
    use std::io::Write as _;
    use std::os::fd::AsFd as _;

    let (mut node, log) = prepared_hot_fork_node_with_log(DescriptorScript::Success)?;
    let directory = tempfile::tempdir()?;
    let vmstate = std::fs::File::create(directory.path().join("vmstate.qcow2"))?;
    let overlay = std::fs::File::create(directory.path().join("overlay.qcow2"))?;
    let vmstate_root = crate::QmpHotForkChildFileRoot::node_name("vmstate")?;
    let overlay_root = crate::QmpHotForkChildFileRoot::device("crucible-root0")?;
    let destinations = [
        crate::QemuHotForkChildFileDestination::new(&vmstate_root, vmstate.as_fd()),
        crate::QemuHotForkChildFileDestination::new(&overlay_root, overlay.as_fd()),
    ];

    // Unbounded budgets, zero template generations, and duplicate roots are
    // rejected before any descriptor reaches QEMU.
    assert!(
        node.stage_hot_fork_child_files(&destinations, 0, 1)
            .is_err()
    );
    assert!(
        node.stage_hot_fork_child_files(&destinations, 1 << 20, 0)
            .is_err()
    );
    let duplicate_root = [
        destinations[0],
        crate::QemuHotForkChildFileDestination::new(&vmstate_root, overlay.as_fd()),
    ];
    assert!(
        node.stage_hot_fork_child_files(&duplicate_root, 1 << 20, 1)
            .is_err()
    );
    assert!(node.hot_fork_child_files_stage().is_none());
    assert_eq!(node.lifecycle_state(), QemuNodeLifecycleState::Running);

    let proof = node.stage_hot_fork_child_files(&destinations, 1 << 20, 1)?;
    assert_eq!(proof.generation(), 17);
    assert_eq!(proof.template_generation(), 1);
    assert_eq!(proof.maximum_bytes(), 1 << 20);
    assert_eq!(proof.file_count(), 2);
    assert!(!proof.consumed());
    assert!(
        node.stage_hot_fork_child_files(&destinations, 1 << 20, 1)
            .is_err()
    );

    let released = node.release_hot_fork_child_files()?;
    assert!(!released.staged());
    assert_eq!(released.generation(), 17);
    assert!(node.hot_fork_child_files_stage().is_none());
    assert!(node.release_hot_fork_child_files().is_err());

    let mut nonempty = std::fs::File::create(directory.path().join("nonempty.qcow2"))?;
    nonempty.write_all(b"x")?;
    let nonempty_destinations = [crate::QemuHotForkChildFileDestination::new(
        &vmstate_root,
        nonempty.as_fd(),
    )];
    assert!(
        node.stage_hot_fork_child_files(&nonempty_destinations, 1 << 20, 1)
            .is_err()
    );
    assert_eq!(node.lifecycle_state(), QemuNodeLifecycleState::Running);

    let calls = recorded(&log);
    assert_eq!(
        calls
            .iter()
            .filter(|call| matches!(call, ChannelCall::QmpHotForkInstallChildFiles))
            .count(),
        1
    );
    assert_eq!(
        calls
            .iter()
            .filter(|call| matches!(call, ChannelCall::QmpHotForkReleaseChildFiles))
            .count(),
        1
    );
    node.shutdown_child()?;
    Ok(())
}

#[test]
#[cfg(target_os = "linux")]
fn hot_fork_consumes_the_staged_child_file_plan() -> Result<(), Box<dyn Error>> {
    use std::os::fd::AsFd as _;

    let (mut node, log) = sealed_hot_fork_node_with_log(DescriptorScript::Success)?;
    let directory = tempfile::tempdir()?;
    let vmstate = std::fs::File::create(directory.path().join("vmstate.qcow2"))?;
    let vmstate_root = crate::QmpHotForkChildFileRoot::node_name("vmstate")?;
    let destinations = [crate::QemuHotForkChildFileDestination::new(
        &vmstate_root,
        vmstate.as_fd(),
    )];
    let proof = node.stage_hot_fork_child_files(&destinations, 1 << 20, 1)?;
    let mut process_owner = ScriptedHotForkChildOwner::default();

    let launch = node.fork_prepared_hot_fork_template(&mut process_owner)?;

    // The derived request carries QEMU's exact plan generation, and a
    // successful fork consumes the node-owned stage exactly once.
    assert_eq!(
        launch.parent_state().request().child_files_generation(),
        proof.generation()
    );
    assert!(
        node.hot_fork_child_files_stage()
            .is_some_and(|stage| stage.consumed())
    );
    let calls = recorded(&log);
    let stage = calls
        .iter()
        .position(|call| matches!(call, ChannelCall::QmpHotForkInstallChildFiles))
        .ok_or("child file stage was not recorded")?;
    let query = calls
        .iter()
        .position(|call| matches!(call, ChannelCall::QmpHotForkChildFiles))
        .ok_or("child file query was not recorded")?;
    let fork = calls
        .iter()
        .position(|call| matches!(call, ChannelCall::QmpHotFork))
        .ok_or("hot fork was not recorded")?;
    assert!(stage < query && query < fork);

    drop(launch);
    node.shutdown_child()?;
    Ok(())
}

#[test]
#[cfg(target_os = "linux")]
fn successful_child_file_proof_seals_only_its_exact_destination_pair() -> Result<(), Box<dyn Error>>
{
    use std::io::Read as _;
    let requirements = crate::QemuLaunchResourceRequirements::from_vm_shape(1, 1, true);
    let contract = unvalidated_hot_fork_process_contract()?;
    let first_root = tempfile::tempdir()?;
    let second_root = tempfile::tempdir()?;
    for root in [first_root.path(), second_root.path()] {
        std::fs::File::create(root.join(crate::DEFAULT_VMSTATE_FILE_NAME))?;
        std::fs::File::create(root.join(crate::DEFAULT_ROOT_OVERLAY_FILE_NAME))?;
    }
    let mut first = crate::QemuPreparedRunDirectory::open_for_test_requirements(
        requirements,
        first_root.path(),
        &contract,
    )?;
    let mut second = crate::QemuPreparedRunDirectory::open_for_test_requirements(
        requirements,
        second_root.path(),
        &contract,
    )?;
    std::fs::write(
        second_root.path().join(crate::DEFAULT_VMSTATE_FILE_NAME),
        b"foreign-vmstate",
    )?;
    std::fs::write(
        second_root
            .path()
            .join(crate::DEFAULT_ROOT_OVERLAY_FILE_NAME),
        b"foreign-overlay",
    )?;

    let mut node = crate::node::test_support::hot_fork::scripted_hot_fork_source_for_test(
        crate::node::test_support::hot_fork::QemuTestHotForkOutcome::Forked,
    )?;
    node.prepare_hot_fork_child_resources(usize::MAX)?;
    let vmstate_root = crate::QmpHotForkChildFileRoot::node_name(crate::DEFAULT_VMSTATE_NODE_NAME)?;
    let overlay_root = crate::QmpHotForkChildFileRoot::device(crate::ROOT_DRIVE_ID)?;
    let destinations = [
        crate::QemuHotForkChildFileDestination::new(
            &vmstate_root,
            first.hot_fork_child_file_destination()?,
        ),
        crate::QemuHotForkChildFileDestination::new(
            &overlay_root,
            first.hot_fork_root_overlay_destination()?,
        ),
    ];
    let mut process_owner = ScriptedHotForkTargetOwner {
        contract,
        retained: Vec::new(),
    };
    let launch = node.fork_prepared_hot_fork_template_with_files_into(
        &mut process_owner,
        |owner| Ok(&owner.contract),
        &destinations,
        1 << 30,
    )?;

    assert!(second.seal_hot_fork_child_file_transfer(&launch).is_err());
    assert!(first.validate_hot_fork_adoption().is_err());
    first.seal_hot_fork_child_file_transfer(&launch)?;
    first.validate_hot_fork_adoption()?;
    let mut vmstate = String::new();
    let mut overlay = String::new();
    std::fs::File::open(first_root.path().join(crate::DEFAULT_VMSTATE_FILE_NAME))?
        .read_to_string(&mut vmstate)?;
    std::fs::File::open(
        first_root
            .path()
            .join(crate::DEFAULT_ROOT_OVERLAY_FILE_NAME),
    )?
    .read_to_string(&mut overlay)?;
    assert_eq!(vmstate, "scripted-hot-fork-vmstate-v1\n");
    assert_eq!(overlay, "scripted-hot-fork-root-overlay-v1\n");
    assert_eq!(
        std::fs::read(second_root.path().join(crate::DEFAULT_VMSTATE_FILE_NAME))?,
        b"foreign-vmstate"
    );
    assert_eq!(
        std::fs::read(
            second_root
                .path()
                .join(crate::DEFAULT_ROOT_OVERLAY_FILE_NAME)
        )?,
        b"foreign-overlay"
    );

    let renamed_root = first_root.path().with_extension("renamed");
    std::fs::rename(first_root.path(), &renamed_root)?;
    assert!(matches!(
        first.validate_hot_fork_adoption(),
        Err(crate::QemuSpawnError::PreparedRunDirectoryChanged { .. })
    ));
    std::fs::rename(&renamed_root, first_root.path())?;
    first.validate_hot_fork_adoption()?;

    let overlay_path = first_root
        .path()
        .join(crate::DEFAULT_ROOT_OVERLAY_FILE_NAME);
    let retained_overlay = first_root.path().join("retained-overlay.qcow2");
    std::fs::rename(&overlay_path, &retained_overlay)?;
    std::os::unix::fs::symlink(
        second_root
            .path()
            .join(crate::DEFAULT_ROOT_OVERLAY_FILE_NAME),
        &overlay_path,
    )?;
    assert!(first.open_root_overlay_for_checkpoint().is_err());
    std::fs::remove_file(&overlay_path)?;
    std::fs::write(&overlay_path, b"replacement-overlay")?;
    assert!(matches!(
        first.open_root_overlay_for_checkpoint(),
        Err(crate::QemuSpawnError::PreparedRootOverlayChanged { .. })
    ));
    std::fs::remove_file(&overlay_path)?;
    std::fs::rename(&retained_overlay, &overlay_path)?;
    let mut checkpoint_overlay = String::new();
    first
        .open_root_overlay_for_checkpoint()?
        .read_to_string(&mut checkpoint_overlay)?;
    assert_eq!(checkpoint_overlay, "scripted-hot-fork-root-overlay-v1\n");

    drop(launch);
    node.shutdown_child()?;
    Ok(())
}
