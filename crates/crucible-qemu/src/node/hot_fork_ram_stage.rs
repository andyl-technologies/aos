//! Fresh child RAM descriptor custody retained across native fork staging.
//!
//! The immutable plan is a portable byte record in a sealed memfd. Connected
//! sockets and anonymous disk preservation are independent descriptors; this
//! host never duplicates an inherited userfaultfd or native RAM registration.

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::sync::Arc;

use crucible_linux_resource::host_services::HostServiceLease;
use crucible_linux_resource::host_supervision::{HostOperationClass, HostOperationSupervisor};
use crucible_protocol::ram_control::{RamControlFrame, RamControlMessage, RamControlRequest};
use crucible_protocol::ram_fork::{RamForkPlan, RamForkSource};
use crucible_protocol::ram_page::RamPageBinding;

use super::*;
use crate::launch_cleanup::{LaunchCleanup, LaunchDescriptorImport};
use crate::qmp::{QmpHotForkChildRamDescriptors, QmpHotForkChildRamNames, QmpHotForkChildRamState};
use crate::ram_control::{
    RamControlRegistration, outer_cap_to_wire, policy_to_wire, resources_to_wire, target_to_wire,
};
use crate::ram_source::{QemuRamBacking, QemuRamSourceService};

pub(super) struct QemuHotForkRamStage {
    names: QmpHotForkChildRamNames,
    plan: Option<OwnedFd>,
    control_host: Option<UnixStream>,
    control_child: UnixStream,
    source_child: Option<UnixStream>,
    source_service: Option<Box<QemuRamSourceService>>,
    source_record: Option<RamForkSource>,
    spill: OwnedFd,
    session: [u8; 32],
    registration: RamControlRegistration,
    supervisor: HostOperationSupervisor,
    state: Option<QmpHotForkChildRamState>,
    imported: Option<LaunchDescriptorImport>,
    service_lease: HostServiceLease,
    parent_cleanup: Option<LaunchCleanup>,
    cleanup: LaunchCleanup,
}

impl QemuHotForkRamStage {
    fn prepare(
        registration: RamControlRegistration,
        supervisor: HostOperationSupervisor,
        directory: &crate::QemuPreparedRunDirectory,
        source: Option<(Arc<dyn QemuRamBacking>, RamPageBinding)>,
        cleanup: LaunchCleanup,
    ) -> Result<Self, QemuNodeChannelError> {
        // The first local remains after every fallible descriptor/worker local
        // is destroyed. Failed native transfers later add independent custody.
        if registration.target.retained_template {
            return Err(failure("child admission names a retained template"));
        }
        let guard = supervisor
            .begin(HostOperationClass::Preparation)
            .map_err(failure)?;
        guard.wait_slice().map_err(failure)?;
        let root_bytes = source
            .as_ref()
            .map_or(0, |(backing, _)| backing.root_record().encoded_len());
        if root_bytes > crucible_protocol::ram_fork::RAM_FORK_ROOT_MAX_BYTES {
            return Err(failure("source metadata exceeds child plan bound"));
        }
        // Account simultaneous source metadata, temporary plan copies and the
        // sealed memfd pages. Encoding size comes from the canonical codec,
        // rather than charging every small VM the maximum topology allowance.
        let fixed_plan_bytes = crucible_protocol::ram_fork::RAM_FORK_HEADER_BYTES
            + crucible_protocol::ram_control::RAM_CONTROL_MAX_BYTES
            + 4
            + crucible_protocol::ram_control::RAM_CONTROL_OUTER_BYTES;
        let scratch_bytes = root_bytes
            .checked_mul(4)
            .and_then(|bytes| bytes.checked_add(2 * fixed_plan_bytes + rustix::param::page_size()))
            .ok_or_else(|| failure("child plan scratch admission overflow"))?;
        let service_lease = registration
            .host_services
            .reserve_resources(0, 16, scratch_bytes as u64)
            .map_err(failure)?;
        let session = entropy::<32>()?;
        let suffix: String = session[..12]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let name = |role| {
            crate::QmpDescriptorName::new(format!("ram-child-{suffix}-{role}")).map_err(failure)
        };
        let names = QmpHotForkChildRamNames {
            plan: name("plan")?,
            control: name("control")?,
            source: source.as_ref().map(|_| name("source")).transpose()?,
            spill: name("spill")?,
        };
        let (control_host, control_child) = UnixStream::pair().map_err(failure)?;
        let spill = directory
            .create_hot_fork_ram_spill(registration.spill_quota_bytes)
            .map_err(failure)?;
        let (source_child, source_service, source_record) = match source {
            Some((backing, binding)) => {
                let root_record = backing.root_record().try_encode().map_err(failure)?;
                if root_record.len() > crucible_protocol::ram_fork::RAM_FORK_ROOT_MAX_BYTES {
                    return Err(failure("source metadata exceeds child plan bound"));
                }
                let (host, child) = UnixStream::pair().map_err(failure)?;
                let service = QemuRamSourceService::start_with_cleanup(
                    host,
                    backing,
                    binding,
                    supervisor.clone(),
                    registration.host_services.clone(),
                    Some(cleanup.clone()),
                )
                .map_err(failure)?;
                (
                    Some(child),
                    Some(Box::new(service)),
                    Some(RamForkSource {
                        binding,
                        root_record,
                    }),
                )
            }
            None => (None, None, None),
        };
        let stage = Self {
            names,
            plan: None,
            control_host: Some(control_host),
            control_child,
            source_child,
            source_service,
            source_record,
            spill,
            session,
            registration,
            supervisor,
            state: None,
            imported: None,
            service_lease,
            parent_cleanup: None,
            cleanup,
        };
        guard.complete().map_err(failure)?;
        Ok(stage)
    }

    fn seal(&mut self, template: u64, contract: u64) -> Result<(), QemuNodeChannelError> {
        if self.plan.is_some() || self.imported.is_some() {
            return Err(failure("RAM plan already sealed"));
        }
        let guard = self
            .supervisor
            .begin(HostOperationClass::Preparation)
            .map_err(failure)?;
        guard.wait_slice().map_err(failure)?;
        let plan = RamForkPlan {
            template_generation: template,
            process_contract_generation: contract,
            resources: resources_to_wire(self.registration.resources),
            spill_quota_bytes: self.registration.spill_quota_bytes,
            control: RamControlFrame {
                session: self.session,
                sequence: 1,
                target: target_to_wire(self.registration.target),
                message: RamControlMessage::Request(RamControlRequest::Apply {
                    expected_revision: 0,
                    policy_revision: 1,
                    reservation_revision: 0,
                    policy: policy_to_wire(self.registration.initial_policy).map_err(failure)?,
                    resources: resources_to_wire(self.registration.resources),
                }),
            },
            outer_cap: outer_cap_to_wire(self.supervisor.outer_cap_binding().map_err(failure)?)
                .map_err(failure)?,
            source: self.source_record.clone(),
        };
        self.plan = Some(sealed_plan(&plan.encode().map_err(failure)?)?);
        guard.complete().map_err(failure)?;
        Ok(())
    }

    pub(super) fn child_created(&self) {
        self.cleanup.child_started();
    }

    pub(super) fn bind_process(
        &self,
        basis: crate::QemuHotForkChildProcessBasis,
    ) -> Result<(), QemuNodeChannelError> {
        self.cleanup.bind_external_process(basis).map_err(failure)
    }

    pub(super) fn take_continuation(
        &mut self,
    ) -> Result<QemuHotForkRamContinuation, QemuNodeChannelError> {
        let control = self
            .control_host
            .take()
            .ok_or_else(|| failure("RAM controller already transferred"))?;
        Ok(QemuHotForkRamContinuation {
            control: Some(control),
            source: self.source_service.take(),
            session: self.session,
            registration: self.registration.clone(),
            supervisor: self.supervisor.clone(),
            service_lease: self.service_lease.clone(),
            cleanup: self.cleanup.clone(),
        })
    }
}

impl Drop for QemuHotForkRamStage {
    fn drop(&mut self) {
        if self
            .parent_cleanup
            .as_ref()
            .is_some_and(LaunchCleanup::process_reaped)
            && let Some(imported) = &mut self.imported
        {
            imported.closed();
        }
        // Closing our unused peer precedes the bounded source join. Unknown
        // monitor/native duplicates keep their independent import ticket open.
        self.source_child.take();
        if let Some(source) = self.source_service.take()
            && let Err(error) = source.stop()
        {
            self.source_service = Some(error.service);
        }
    }
}

pub(super) struct QemuHotForkRamContinuation {
    control: Option<UnixStream>,
    pub(super) source: Option<Box<QemuRamSourceService>>,
    session: [u8; 32],
    registration: RamControlRegistration,
    supervisor: HostOperationSupervisor,
    service_lease: HostServiceLease,
    pub(super) cleanup: LaunchCleanup,
}

impl QemuHotForkRamContinuation {
    pub(super) fn activate(&mut self) -> Result<(), QemuNodeChannelError> {
        let stream = self
            .control
            .take()
            .ok_or_else(|| failure("RAM controller already activated"))?;
        let mut client = crate::ram_control::RamControlClient::connect_supervised(
            stream,
            self.session,
            self.registration.target,
            self.supervisor.clone(),
        )
        .map_err(failure)?;
        client.retain_launch_cleanup(self.cleanup.clone());
        client
            .retain_host_service_lease(self.service_lease.clone())
            .map_err(failure)?;
        let state = client.status().map_err(failure)?;
        if state.requested_policy_revision != 1
            || state.applied_policy_revision != 1
            || state.reservation_revision != 0
            || state.logical_ram_bytes == 0
        {
            return Err(failure(
                "child RAM reconstruction lacks applied initial grant",
            ));
        }
        self.registration
            .registrar
            .register(
                self.registration.target,
                self.registration.initial_policy,
                self.registration.resources,
                self.supervisor.clone(),
                Some(client),
            )
            .map_err(failure)?;
        self.cleanup.published().map_err(failure)
    }

    pub(super) fn finish(&mut self) -> Result<(), QemuNodeChannelError> {
        if let Some(source) = self.source.take()
            && let Err(error) = source.stop()
        {
            self.source = Some(error.service);
            return Err(failure(error.source));
        }
        if self.cleanup.is_published() {
            self.registration
                .registrar
                .prepare_retirement_after_cleanup(self.registration.target)
                .map_err(failure)?;
        }
        Ok(())
    }
}

impl Drop for QemuHotForkRamContinuation {
    fn drop(&mut self) {
        if self.cleanup.cleanup_proven() {
            let _ = self.finish();
        } else {
            self.cleanup.quarantine();
        }
    }
}

impl QemuNode {
    pub(crate) fn prepare_hot_fork_child_ram(
        &mut self,
        registration: RamControlRegistration,
        supervisor: HostOperationSupervisor,
        directory: &crate::QemuPreparedRunDirectory,
        custody: crate::QemuRamLaunchCustody,
    ) -> Result<(), QemuNodeChannelError> {
        if !custody.validates(&registration) {
            return Err(failure(
                "child custody differs from retained launch admission",
            ));
        }
        let cleanup = custody.cleanup.clone();
        if self.hot_fork_ram_stage.is_some() {
            return Err(failure("RAM child stage already retained"));
        }
        let parent_source = match &self.child {
            QemuNodeProcessControl::Direct(child) => child.ram_source.as_deref(),
            QemuNodeProcessControl::External(_) => self
                .hot_fork_ram_continuation
                .as_ref()
                .and_then(|ram| ram.source.as_deref()),
        };
        let source = parent_source
            .map(|source| {
                let binding = RamPageBinding {
                    session: entropy::<16>()?,
                    owner_incarnation: entropy::<16>()?,
                    source_generation: registration.target.arena_generation,
                    root_digest: source.binding().root_digest,
                };
                Ok::<_, QemuNodeChannelError>((
                    source.child_backing(binding).map_err(failure)?,
                    binding,
                ))
            })
            .transpose()?;
        self.hot_fork_ram_stage = Some(Box::new(QemuHotForkRamStage::prepare(
            registration,
            supervisor,
            directory,
            source,
            cleanup,
        )?));
        if let Some(stage) = &mut self.hot_fork_ram_stage {
            stage.parent_cleanup = self._launch_cleanup.clone();
        }
        Ok(())
    }

    pub(super) fn validate_hot_fork_ram_stage(
        &mut self,
        template: u64,
        contract: u64,
        consumed: bool,
    ) -> Result<(), QemuNodeChannelError> {
        let Some(stage) = &self.hot_fork_ram_stage else {
            return Ok(());
        };
        let expected = stage
            .state
            .ok_or_else(|| failure("RAM stage lacks native custody acknowledgement"))?;
        let observed = self
            .channels
            .qmp_machine_control
            .query_hot_fork_child_ram()?;
        if !observed.staged
            || observed.generation != expected.generation
            || observed.template_generation != template
            || observed.process_contract_generation != contract
            || observed.consumed != consumed
            || observed.source_bound != stage.source_record.is_some()
        {
            return Err(failure("native RAM custody differs from exact fork stage"));
        }
        Ok(())
    }

    pub(super) fn install_hot_fork_ram_stage(
        &mut self,
        template: u64,
        contract: u64,
    ) -> Result<(), QemuNodeChannelError> {
        let Some(stage) = &mut self.hot_fork_ram_stage else {
            return Ok(());
        };
        stage.seal(template, contract)?;
        let plan = stage
            .plan
            .as_ref()
            .ok_or_else(|| failure("sealed RAM plan absent"))?;
        stage.imported = Some(stage.cleanup.descriptor_import().map_err(failure)?);
        let state = self
            .channels
            .qmp_machine_control
            .install_hot_fork_child_ram(
                &stage.names,
                QmpHotForkChildRamDescriptors {
                    plan: plan.as_fd(),
                    control: stage.control_child.as_fd(),
                    source: stage.source_child.as_ref().map(AsFd::as_fd),
                    spill: stage.spill.as_fd(),
                },
                template,
                contract,
            )
            .inspect_err(|_| {
                self.lifecycle_state = QemuNodeLifecycleState::Quarantined;
            })?;
        stage.state = Some(state);
        Ok(())
    }

    pub(super) fn release_hot_fork_ram_stage(&mut self) -> Result<(), QemuNodeChannelError> {
        let Some(stage) = &mut self.hot_fork_ram_stage else {
            return Ok(());
        };
        if let Some(state) = stage.state {
            self.channels
                .qmp_machine_control
                .close_hot_fork_child_ram(&stage.names, state.generation)?;
            if let Some(imported) = &mut stage.imported {
                imported.closed();
            }
        } else if stage.imported.is_some() {
            return Err(failure("RAM monitor ownership is uncertain"));
        }
        self.hot_fork_ram_stage = None;
        Ok(())
    }
}

fn failure(error: impl std::fmt::Display) -> QemuNodeChannelError {
    QemuNodeChannelError::new("prepare independent child RAM", error.to_string())
}

fn entropy<const N: usize>() -> Result<[u8; N], QemuNodeChannelError> {
    let mut bytes = [0; N];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(failure)?;
    if bytes == [0; N] {
        return Err(failure("empty fresh RAM namespace"));
    }
    Ok(bytes)
}

fn sealed_plan(bytes: &[u8]) -> Result<OwnedFd, QemuNodeChannelError> {
    use rustix::fs::{MemfdFlags, SealFlags, fcntl_add_seals, memfd_create};
    let descriptor = memfd_create(
        "crucible-child-ram-plan",
        MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
    )
    .map_err(failure)?;
    let mut file = File::from(descriptor);
    file.write_all(bytes).map_err(failure)?;
    fcntl_add_seals(
        &file,
        SealFlags::SHRINK | SealFlags::GROW | SealFlags::WRITE | SealFlags::SEAL,
    )
    .map_err(failure)?;
    Ok(file.into())
}

#[cfg(test)]
#[path = "hot_fork_ram_stage/tests.rs"]
mod tests;
