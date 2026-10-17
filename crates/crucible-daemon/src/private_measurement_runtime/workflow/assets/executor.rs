//! Builds the explicit executor contract from the authenticated workflow.
//!
//! The same artifact budget admits every retained path, campaign-set node and
//! immediate configuration allocation before construction. Publication precedes
//! independent sticky and raw original postchecks. This stage does not bind the
//! endpoint, reopen a catalog or create a native execution owner.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use crucible::owned_decode::json_profiles::workflow::{
    ExecutorDeployment, ExecutorOperationBudget, ExecutorOperationBudgets, WorkflowProjection,
};
use crucible_api::host_operational::{
    HostOperationBudget, HostOperationBudgets, HostResourceVector,
};
use crucible_campaign::{AttemptResourceLimits, CampaignName, DaemonEpoch};

use crate::{
    ExecutorCapacity, ExecutorLoopbackEndpointConfig, ExecutorLoopbackServerConfig,
    HostOperationalCapacity, LoopbackExecutorTimeouts, PackagedQemuExecutorConfig,
};

use super::*;

mod campaign_execution;

// Matches the resident-throughput executor declaration in
// packaged_qemu_executor/tests/paging_native/throughput/corpus.rs. Dirty-unit
// capacity is a different resource axis even where the authored values agree.
const MAXIMUM_CORPUS_EXECUTION_QUANTA: u64 = 150_000;

impl OriginalWorkflowArtifactsOwner {
    /// Moves the prepared config while retaining its original pins and custody.
    ///
    /// # Errors
    /// Refuses missing publication or the original boundary. A pre-factory late
    /// refusal frees the local config before this owner's credit; a successful
    /// handoff retains the lifecycle Arc, preventing artifact closure while the
    /// real factory uses it. No copied configuration or replacement credit exists.
    pub(in crate::private_measurement_runtime::workflow) fn take_executor_config(
        &mut self,
        service: &OriginalPreparedCampaignServiceOwner,
    ) -> Result<PackagedQemuExecutorConfig, OriginalWorkflowArtifactsError> {
        let original = || service.verify_original();
        let mut failure = ArtifactFailurePurpose::prepare(&self.budget, &original)?;
        let result = {
            let check = failure.work(&original);
            let work = (|| {
                check.verify_original()?;
                self.budget.verify_live()?;
                if self.closed {
                    return Err(ArtifactCause::Identity);
                }
                self.executor_config.take().ok_or(ArtifactCause::Identity)
            })();
            checked(&check, work)
        };
        failure.finish(result).map(|config| *config)
    }

    /// Constructs and publishes the paid configuration with its original catalog.
    ///
    /// # Errors
    /// Refuses foreign input, repeated publication, original admission, invalid
    /// required executor contracts or the actual constructors and quota binding.
    pub(in crate::private_measurement_runtime::workflow) fn prepare_executor_config(
        &mut self,
        bytes: &[u8],
        state: &crate::campaign_bootstrap::OriginalCampaignStateBootstrap,
        service: &OriginalPreparedCampaignServiceOwner,
        catalog: &crate::private_measurement_runtime::catalog::OriginalRamCatalogBinding,
    ) -> Result<(), OriginalWorkflowArtifactsError> {
        let original = || service.verify_original();
        let mut failure = ArtifactFailurePurpose::prepare(&self.budget, &original)?;
        let result = {
            let check = failure.work(&original);
            let work = (|| {
                check.verify_original()?;
                self.budget.verify_live()?;
                if self.closed || self.executor_config.is_some() {
                    return Err(ArtifactCause::Identity);
                }
                let _scope = self.budget.enter();
                let workflow: WorkflowProjection<'_> = from_json_slice_closed(bytes, &self.budget)?;
                validate_geometry(&workflow)?;
                let input = &workflow.service_profile.operator.executor;
                let projection = self.projection.as_ref().ok_or(ArtifactCause::Identity)?;
                if workflow.native_count != projection.native_count as u64
                    || input.worker_count != projection.native_count
                    || input.assignment_resources != workflow.service_profile.native
                    || workflow.service_profile.preparation_seconds != 3600
                    || workflow.service_profile.invocation_seconds != 3900
                {
                    return Err(ArtifactCause::Identity);
                }
                let root = state.run_state_root()?;
                let config = build(input, root, self, campaigns(self)?)?
                    .with_original_catalog(catalog.clone())?
                    .with_operational_registry_resources(vector(
                        workflow.service_profile.operator.registry,
                    ))?
                    .with_operational_registry_quota(
                        workflow.service_profile.operator.registry_project_id,
                        workflow.service_profile.operator.registry_maximum_inodes,
                    )?;
                self.budget.charge_array::<PackagedQemuExecutorConfig>(1)?;
                self.executor_config = Some(Box::new(config));
                self.budget.verify_live()?;
                Ok(())
            })();
            checked(&check, work)
        };
        failure.finish(result)
    }
}

fn validate_geometry(workflow: &WorkflowProjection<'_>) -> Result<(), ArtifactCause> {
    let profile = &workflow.service_profile;
    let input = &profile.operator.executor;
    campaign_execution::validate(&input.campaign_execution)?;
    let capacity = &input.capacity;
    let operational = &input.host_operational_capacity;
    let aggregate = &profile.aggregate;
    if u64::from(capacity.maximum_concurrent_executions) != aggregate.native_slots
        || u64::from(capacity.maximum_vcpus) != aggregate.cpu_slots
        || capacity.maximum_resident_bytes != aggregate.resident_bytes
        || capacity.maximum_disk_bytes != aggregate.backing_bytes
        || capacity.maximum_execution_quanta != MAXIMUM_CORPUS_EXECUTION_QUANTA
        || operational.maximum_paging_io_slots != aggregate.paging_io_slots
        || operational.maximum_task_slots != aggregate.task_slots
        || operational.maximum_file_descriptors != aggregate.file_descriptors
        || operational.maximum_metadata_bytes != aggregate.metadata_bytes
        || operational.maximum_staging_bytes != aggregate.staging_bytes
        || input.assignment_resources != profile.native
        || input.worker_count as u64 != workflow.native_count
        || input.endpoint.owner_user_id != rustix::process::geteuid().as_raw()
        || input.endpoint.owner_group_id != rustix::process::getegid().as_raw()
        || input.execution_profile.is_empty()
        || input.execution_profile.as_bytes().contains(&0)
        || profile.preparation_seconds != 3600
        || profile.invocation_seconds != 3900
        || input.host_operation_budgets.preparation.total_millis
            != Some(
                profile
                    .preparation_seconds
                    .checked_mul(1000)
                    .ok_or(ArtifactCause::Identity)?,
            )
    {
        return Err(ArtifactCause::Identity);
    }
    let maximum = profile
        .invocation_seconds
        .checked_mul(1000)
        .ok_or(ArtifactCause::Identity)?;
    let budgets = operation_budgets(&input.host_operation_budgets)?;
    for class in crucible_api::host_operational::HostOperationClass::ALL {
        let budget = budgets.get(class);
        if budget.poll_interval > Duration::from_millis(maximum)
            || budget
                .progress_timeout
                .is_some_and(|duration| duration > Duration::from_millis(maximum))
            || budget
                .total_timeout
                .is_some_and(|duration| duration > Duration::from_millis(maximum))
        {
            return Err(ArtifactCause::Identity);
        }
    }
    Ok(())
}

fn build(
    input: &ExecutorDeployment<'_>,
    root: &Path,
    owner: &OriginalWorkflowArtifactsOwner,
    campaigns: BTreeSet<CampaignName>,
) -> Result<PackagedQemuExecutorConfig, ArtifactCause> {
    let budget = &owner.budget;
    let requirements = requirements(input, budget)?;
    let budgets = operation_budgets(&input.host_operation_budgets)?;
    let ledger = ledger_path(root, input.ledger_directory, budget)?;
    let epoch = DaemonEpoch::from_bytes(input.daemon_epoch)?;
    let profile = string(input.execution_profile, budget)?;
    let architecture = string("x86_64", budget)?;
    // This alias retains the actual admitted body and every authenticated pin.
    // Sharing it creates no second lifecycle allocation or entitlement.
    let lifecycle = std::sync::Arc::clone(owner.lifecycle.as_ref().ok_or(ArtifactCause::Identity)?);
    PackagedQemuExecutorConfig::new(
        campaigns,
        requirements.endpoint,
        requirements.server,
        ledger,
        input.maximum_checkpoint_bytes,
        epoch,
        requirements.capacity,
        requirements.operational,
        input.worker_count,
        architecture,
        profile,
        input.store_namespace,
        lifecycle,
        requirements.host,
    )?
    .with_assignment_resources(vector(input.assignment_resources), requirements.limits)?
    .with_host_operation_budgets(budgets)
    .map_err(Into::into)
}

struct ExecutorRequirements {
    endpoint: ExecutorLoopbackEndpointConfig,
    server: ExecutorLoopbackServerConfig,
    capacity: ExecutorCapacity,
    operational: HostOperationalCapacity,
    limits: AttemptResourceLimits,
    host: crucible_qemu::LinuxQemuAttemptHostConfig,
}

fn requirements(
    input: &ExecutorDeployment<'_>,
    budget: &DecodeBudget,
) -> Result<ExecutorRequirements, ArtifactCause> {
    let endpoint = ExecutorLoopbackEndpointConfig::new(
        path(input.endpoint.path, budget)?,
        input.endpoint.owner_user_id,
        input.endpoint.owner_group_id,
        input.endpoint.socket_mode,
    )?;
    let server = ExecutorLoopbackServerConfig::new(
        input.server.connection_workers,
        input.server.pending_connections,
        input.server.maximum_requests_per_connection,
        Duration::from_millis(input.server.accept_poll_millis),
        LoopbackExecutorTimeouts::new(
            Duration::from_millis(input.server.read_timeout_millis),
            Duration::from_millis(input.server.write_timeout_millis),
        )?,
    )?;
    let capacity = ExecutorCapacity::new(
        input.capacity.maximum_concurrent_executions,
        input.capacity.maximum_vcpus,
        input.capacity.maximum_resident_bytes,
        input.capacity.maximum_disk_bytes,
        input.capacity.maximum_execution_quanta,
    )?;
    let operational = HostOperationalCapacity::new(
        input.host_operational_capacity.maximum_paging_io_slots,
        input.host_operational_capacity.maximum_task_slots,
        input.host_operational_capacity.maximum_file_descriptors,
        input.host_operational_capacity.maximum_metadata_bytes,
        input.host_operational_capacity.maximum_staging_bytes,
    )?;
    let limits = AttemptResourceLimits::new(
        input.assignment_limits.maximum_vcpus,
        input.assignment_limits.maximum_resident_bytes,
        input.assignment_limits.maximum_disk_bytes,
        input.assignment_limits.maximum_execution_quanta,
    )?;
    let host =
        crucible_qemu::LinuxQemuAttemptHostConfig::try_from_workflow_admitted(&input.host, budget)?;
    Ok(ExecutorRequirements {
        endpoint,
        server,
        capacity,
        operational,
        limits,
        host,
    })
}

/// Validates all authored constructor requirements before service effects.
/// The temporary owning validation values free under the same account; later
/// retained construction separately admits its actual copies.
pub(in crate::private_measurement_runtime::workflow) fn preflight(
    bytes: &[u8],
    decoder: &crucible_qemu::OriginalActorDecodeOwner,
) -> Result<(), OriginalWorkflowArtifactsError> {
    let budget = decoder
        .budget()
        .map_err(OriginalWorkflowArtifactsError::account)?;
    let original = || decoder.verify_original_boundary();
    let mut failure = ArtifactFailurePurpose::prepare(budget, &original)?;
    let result = {
        let check = failure.work(&original);
        let work = (|| {
            check.verify_original()?;
            budget.verify_live()?;
            let _scope = budget.enter();
            let workflow: WorkflowProjection<'_> = from_json_slice_closed(bytes, budget)?;
            validate_geometry(&workflow)?;
            let input = &workflow.service_profile.operator.executor;
            validate_ledger_component(input.ledger_directory)?;
            DaemonEpoch::from_bytes(input.daemon_epoch)?;
            operation_budgets(&input.host_operation_budgets)?;
            let projection: Projection = from_json_slice_closed(bytes, budget)?;
            let count = projection.validate()?;
            let requirements = requirements(input, budget)?;
            validate_configuration_contract(&workflow, &requirements, count)?;
            drop(requirements);
            Ok(())
        })();
        checked(&check, work)
    };
    failure.finish(result)
}

fn validate_configuration_contract(
    workflow: &WorkflowProjection<'_>,
    requirements: &ExecutorRequirements,
    campaign_count: usize,
) -> Result<(), ArtifactCause> {
    let profile = &workflow.service_profile;
    let input = &profile.operator.executor;
    PackagedQemuExecutorConfig::validate_constructor_contract(
        campaign_count,
        input.worker_count,
        input.maximum_checkpoint_bytes,
        requirements.capacity,
        requirements.operational,
    )?;
    PackagedQemuExecutorConfig::validate_assignment_contract(
        requirements.capacity,
        requirements.operational,
        vector(input.assignment_resources),
        requirements.limits,
    )?;
    let registry = vector(profile.operator.registry);
    if !PackagedQemuExecutorConfig::resource_contract_fits(
        requirements.capacity,
        requirements.operational,
        registry,
    ) {
        return Err(
            crate::PackagedQemuExecutorConfigError::InvalidOperationalRegistryResources.into(),
        );
    }
    PackagedQemuExecutorConfig::validate_registry_quota(
        registry,
        profile.operator.registry_project_id,
        profile.operator.registry_maximum_inodes,
    )?;
    Ok(())
}

fn campaigns(
    owner: &OriginalWorkflowArtifactsOwner,
) -> Result<BTreeSet<CampaignName>, ArtifactCause> {
    let budget = &owner.budget;
    budget.charge_btree_entries::<CampaignName, ()>(owner.models.len())?;
    let mut campaigns = BTreeSet::new();
    for model in &owner.models {
        let request = model.request.as_ref().ok_or(ArtifactCause::Identity)?;
        model
            .response
            .as_ref()
            .ok_or(ArtifactCause::Identity)?
            .validate_for(request)?;
        let name = request.campaign().as_str();
        budget.charge_bytes(name.len() as u64)?;
        if !campaigns.insert(CampaignName::new(name)?) {
            return Err(ArtifactCause::Identity);
        }
    }
    Ok(campaigns)
}

fn ledger_path(root: &Path, name: &str, budget: &DecodeBudget) -> Result<PathBuf, ArtifactCause> {
    validate_ledger_component(name)?;
    let length = root
        .as_os_str()
        .len()
        .checked_add(1)
        .and_then(|length| length.checked_add(name.len()))
        .ok_or(ArtifactCause::Identity)?;
    budget.charge_bytes(length as u64)?;
    let mut value = OsString::new();
    value.try_reserve_exact(length)?;
    value.push(root);
    value.push("/");
    value.push(name);
    Ok(value.into())
}

fn validate_ledger_component(name: &str) -> Result<(), ArtifactCause> {
    let mut components = Path::new(name).components();
    if name.is_empty()
        || name.as_bytes().contains(&0)
        || !matches!(components.next(), Some(Component::Normal(_)))
        || components.next().is_some()
    {
        return Err(ArtifactCause::Identity);
    }
    Ok(())
}

fn path(value: &str, budget: &DecodeBudget) -> Result<PathBuf, ArtifactCause> {
    budget.charge_bytes(value.len() as u64)?;
    let mut path = OsString::new();
    path.try_reserve_exact(value.len())?;
    path.push(value);
    Ok(path.into())
}

fn string(value: &str, budget: &DecodeBudget) -> Result<String, ArtifactCause> {
    budget.charge_bytes(value.len() as u64)?;
    let mut owned = String::new();
    owned.try_reserve_exact(value.len())?;
    owned.push_str(value);
    Ok(owned)
}

fn vector(
    input: crucible::owned_decode::json_profiles::workflow::ResourceVector,
) -> HostResourceVector {
    HostResourceVector {
        resident_peak_bytes: input.resident_peak_bytes,
        backing_peak_bytes: input.backing_peak_bytes,
        metadata_bytes: input.metadata_bytes,
        staging_bytes: input.staging_bytes,
        paging_io_slots: input.paging_io_slots,
        cpu_slots: input.cpu_slots,
        task_slots: input.task_slots,
        file_descriptors: input.file_descriptors,
    }
}

fn operation_budgets(
    input: &ExecutorOperationBudgets,
) -> Result<HostOperationBudgets, ArtifactCause> {
    let budgets = HostOperationBudgets {
        classes: [
            operation(&input.setup),
            operation(&input.quantum),
            operation(&input.page_in),
            operation(&input.writeback),
            operation(&input.fingerprint_initialization),
            operation(&input.fingerprint_update),
            operation(&input.quiescence),
            operation(&input.checkpoint_capture),
            operation(&input.checkpoint_publication),
            operation(&input.restore),
            operation(&input.fork_rearm),
            operation(&input.transfer),
            operation(&input.preparation),
            operation(&input.cleanup),
        ],
    };
    budgets.validate(false)?;
    Ok(budgets)
}

fn operation(input: &ExecutorOperationBudget) -> HostOperationBudget {
    HostOperationBudget {
        poll_interval: Duration::from_millis(input.poll_millis),
        progress_timeout: input.progress_millis.map(Duration::from_millis),
        total_timeout: input.total_millis.map(Duration::from_millis),
    }
}

#[cfg(test)]
mod tests {
    //! These controls exercise paid configuration, not native launch admission.

    use super::*;

    use crate::private_measurement_runtime::catalog::tests::fixture;

    fn deployment() -> Result<ExecutorDeployment<'static>, serde_json::Error> {
        serde_json::from_str(include_str!(
            "../../../../../crucible-qemu/src/linux_attempt_host/original_actor/workflow/executor_fixture.json"
        ))
    }

    #[test]
    fn explicit_classes_preserve_canonical_order_without_defaults()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut input = deployment()?;
        input.host_operation_budgets.page_in.total_millis = Some(1234);
        input.host_operation_budgets.restore.total_millis = Some(5678);

        let budgets = operation_budgets(&input.host_operation_budgets)?;

        use crucible_api::host_operational::HostOperationClass;
        assert_eq!(
            budgets.get(HostOperationClass::PageIn).total_timeout,
            Some(Duration::from_millis(1234))
        );
        assert_eq!(
            budgets.get(HostOperationClass::Restore).total_timeout,
            Some(Duration::from_millis(5678))
        );
        assert_eq!(budgets.get(HostOperationClass::Quantum).total_timeout, None);
        Ok(())
    }

    #[test]
    fn unbounded_infrastructure_class_refuses_instead_of_using_a_default()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut input = deployment()?;
        input.host_operation_budgets.setup.total_millis = None;
        assert!(matches!(
            operation_budgets(&input.host_operation_budgets),
            Err(ArtifactCause::OriginalBoundary(_))
        ));
        Ok(())
    }

    #[test]
    fn actual_configuration_uses_required_inputs_and_frees_before_decoder_close()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_, decoder, catalog) = fixture();
        let budget = decoder.budget()?;
        let directory = tempfile::TempDir::new()?;
        let mut owner = super::super::tests::empty_owner(budget);
        let asset = super::super::tests::input(directory.path());
        super::super::tests::install_configuration_fixture(&mut owner, &asset, directory.path());
        budget.charge_btree_entries::<CampaignName, ()>(1)?;
        budget.charge_bytes("throughput-1000".len() as u64)?;
        let campaigns = BTreeSet::from([CampaignName::new("throughput-1000")?]);
        let input = deployment()?;

        let config = build(&input, directory.path(), &owner, campaigns)?;

        assert_eq!(config.guarded_epoch().as_bytes(), [1; 16]);
        assert_eq!(
            config.assignment_resources(),
            Some(vector(input.assignment_resources))
        );
        assert_eq!(
            config
                .assignment_limits()
                .ok_or("assignment limits disappeared")?
                .maximum_execution_quanta(),
            32
        );
        assert!(config.ram_catalog().is_none());
        drop(config);
        drop(owner.lifecycle.take());
        owner.closed = true;
        drop(owner);
        assert!(catalog.try_close().is_ok());
        assert!(decoder.try_close().is_ok());
        Ok(())
    }

    #[test]
    fn exhausted_original_refuses_before_required_path_copy()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_, decoder, catalog) = fixture();
        let budget = decoder.budget()?;
        assert!(budget.reserve_scratch_bytes(5 << 20).is_err());
        let input = deployment()?;

        let failure = crucible_qemu::LinuxQemuAttemptHostConfig::try_from_workflow_admitted(
            &input.host,
            budget,
        )
        .err()
        .ok_or("exhausted account unexpectedly constructed a host")?;

        drop(failure);
        // This deliberately terminal account is retained; it is not retried.
        drop(catalog);
        drop(decoder);
        Ok(())
    }
    #[test]
    fn closed_workflow_requires_namespace_and_preserves_real_parse_error_custody()
    -> Result<(), Box<dyn std::error::Error>> {
        let source = include_str!(
            "../../../../../crucible-qemu/src/linux_attempt_host/original_actor/workflow/whole_executor_fixture.json"
        );
        let (_, decoder, catalog) = fixture();
        let budget = decoder.budget()?;
        let decoded: WorkflowProjection<'_> = from_json_slice_closed(source.as_bytes(), budget)?;
        assert_eq!(
            decoded
                .service_profile
                .operator
                .executor
                .store_namespace
                .as_bytes(),
            [0; 32]
        );
        drop(decoded);

        let absent = source.replace("        \"storeNamespace\": \"0000000000000000000000000000000000000000000000000000000000000000\",\n", "");
        assert_ne!(absent, source);
        let failure =
            match from_json_slice_closed::<WorkflowProjection<'_>>(absent.as_bytes(), budget) {
                Ok(_) => return Err("omitted required namespace parsed".into()),
                Err(failure) => failure,
            };
        assert!(failure.to_string().contains("storeNamespace"));
        drop(failure);

        let malformed = source.replacen(
            "0000000000000000000000000000000000000000000000000000000000000000",
            "INVALID",
            1,
        );
        let failure =
            match from_json_slice_closed::<WorkflowProjection<'_>>(malformed.as_bytes(), budget) {
                Ok(_) => return Err("malformed namespace parsed".into()),
                Err(failure) => failure,
            };
        assert!(failure.to_string().contains("campaign identity"));
        drop(failure);
        for replacement in ["300", "-1", "\"wrong\""] {
            let malformed = source.replacen(
                "\"daemonEpoch\": [\n          1,",
                &format!("\"daemonEpoch\": [\n          {replacement},"),
                1,
            );
            assert_ne!(malformed, source);
            let failure = match from_json_slice_closed::<WorkflowProjection<'_>>(
                malformed.as_bytes(),
                budget,
            ) {
                Ok(_) => return Err("invalid u8 epoch element parsed".into()),
                Err(failure) => failure,
            };
            assert!(failure.to_string().contains("u8"));
            drop(failure);
        }
        catalog.try_close().map_err(|_| "catalog close refused")?;
        decoder.try_close().map_err(|_| "decoder close refused")?;
        Ok(())
    }

    #[test]
    fn closed_workflow_requires_campaign_execution_and_owns_variant_failures()
    -> Result<(), Box<dyn std::error::Error>> {
        let source = include_str!(
            "../../../../../crucible-qemu/src/linux_attempt_host/original_actor/workflow/whole_executor_fixture.json"
        );
        let (_, decoder, catalog) = fixture();
        let budget = decoder.budget()?;
        let decoded: WorkflowProjection<'_> = from_json_slice_closed(source.as_bytes(), budget)?;
        campaign_execution::validate(
            &decoded.service_profile.operator.executor.campaign_execution,
        )?;
        drop(decoded);

        let begin = source
            .find(",\n        \"campaignExecution\"")
            .ok_or("execution fixture field disappeared")?;
        let end = source[begin..]
            .find("\n      },")
            .ok_or("execution fixture boundary disappeared")?;
        let absent = format!("{}{}", &source[..begin], &source[begin + end..]);
        let failure =
            match from_json_slice_closed::<WorkflowProjection<'_>>(absent.as_bytes(), budget) {
                Ok(_) => return Err("missing execution contract parsed".into()),
                Err(failure) => failure,
            };
        assert!(failure.to_string().contains("campaignExecution"));
        drop(failure);

        let malformed = source.replacen("\"breadthFirst\"", "\"unsupportedSearch\"", 1);
        assert_ne!(malformed, source);
        let failure =
            match from_json_slice_closed::<WorkflowProjection<'_>>(malformed.as_bytes(), budget) {
                Ok(_) => return Err("unsupported search parsed".into()),
                Err(failure) => failure,
            };
        assert!(failure.to_string().contains("breadthFirst"));
        drop(failure);

        let malformed = source.replacen("\"discard\"", "\"unsupportedRetention\"", 1);
        let failure =
            match from_json_slice_closed::<WorkflowProjection<'_>>(malformed.as_bytes(), budget) {
                Ok(_) => return Err("unsupported retention parsed".into()),
                Err(failure) => failure,
            };
        assert!(failure.to_string().contains("retainAlways"));
        drop(failure);
        catalog.try_close().map_err(|_| "catalog close refused")?;
        decoder.try_close().map_err(|_| "decoder close refused")?;
        Ok(())
    }

    #[test]
    fn postpublication_cancellation_retains_config_and_raw_original_cause()
    -> Result<(), Box<dyn std::error::Error>> {
        let (supervisor, decoder, catalog) = fixture();
        let budget = decoder.budget()?;
        let original =
            crate::private_measurement_runtime::catalog::tests::fixture_original(&catalog);
        let check = || original.wait_slice().map(|_| ());
        let directory = tempfile::TempDir::new()?;
        let mut owner = super::super::tests::empty_owner(budget);
        let asset = super::super::tests::input(directory.path());
        super::super::tests::install_configuration_fixture(&mut owner, &asset, directory.path());
        budget.charge_btree_entries::<CampaignName, ()>(1)?;
        budget.charge_bytes(15)?;
        let campaigns = BTreeSet::from([CampaignName::new("throughput-1000")?]);
        let input = deployment()?;
        let mut purpose = ArtifactFailurePurpose::prepare(budget, &check)?;
        let refusal = {
            let work = purpose.work(&check);
            let config = build(&input, directory.path(), &owner, campaigns)?;
            budget.charge_array::<PackagedQemuExecutorConfig>(1)?;
            owner.executor_config = Some(Box::new(config));
            supervisor.cancel()?;
            checked(&work, Err::<(), _>(ArtifactCause::Identity))
        };
        let failure = purpose
            .finish(refusal)
            .err()
            .ok_or("cancellation was lost")?;

        assert!(matches!(failure.cause(), Some(ArtifactCause::Identity)));
        assert!(failure.original_after().is_some());
        assert!(owner.executor_config.is_some());
        assert_eq!(
            std::sync::Arc::strong_count(owner.lifecycle.as_ref().ok_or("lifecycle lost")?),
            2
        );
        drop(failure);
        drop(owner.executor_config.take());
        drop(owner.lifecycle.take());
        owner.closed = true;
        drop(owner);
        // The cancelled original remains terminal; freeing test bodies does not
        // reopen it or claim a successful close on the failed account.
        drop(catalog);
        drop(decoder);
        Ok(())
    }
    #[test]
    fn preflight_reuses_constructor_checks_before_configuration_publication()
    -> Result<(), Box<dyn std::error::Error>> {
        let source = include_str!(
            "../../../../../crucible-qemu/src/linux_attempt_host/original_actor/workflow/whole_executor_fixture.json"
        );
        let (_, decoder, catalog) = fixture();
        let budget = decoder.budget()?;
        let mut workflow: WorkflowProjection<'_> =
            from_json_slice_closed(source.as_bytes(), budget)?;
        // This identity control uses the actual inherited fixture process.
        workflow
            .service_profile
            .operator
            .executor
            .endpoint
            .owner_user_id = rustix::process::geteuid().as_raw();
        workflow
            .service_profile
            .operator
            .executor
            .endpoint
            .owner_group_id = rustix::process::getegid().as_raw();
        let requirements = requirements(&workflow.service_profile.operator.executor, budget)?;
        validate_geometry(&workflow)?;
        validate_configuration_contract(&workflow, &requirements, 9)?;

        workflow
            .service_profile
            .operator
            .executor
            .maximum_checkpoint_bytes = 0;
        assert!(matches!(
            validate_configuration_contract(&workflow, &requirements, 9),
            Err(ArtifactCause::Executor(
                crate::PackagedQemuExecutorConfigError::ZeroCheckpointBytes
            ))
        ));
        workflow
            .service_profile
            .operator
            .executor
            .maximum_checkpoint_bytes = 1;
        workflow.service_profile.operator.executor.worker_count = 5;
        assert!(matches!(
            validate_configuration_contract(&workflow, &requirements, 9),
            Err(ArtifactCause::Executor(
                crate::PackagedQemuExecutorConfigError::WorkersExceedSlots
            ))
        ));
        workflow.service_profile.operator.executor.worker_count = 1;
        workflow.service_profile.operator.registry_project_id = 0;
        assert!(matches!(
            validate_configuration_contract(&workflow, &requirements, 9),
            Err(ArtifactCause::Executor(
                crate::PackagedQemuExecutorConfigError::InvalidOperationalRegistryQuota
            ))
        ));
        workflow.service_profile.preparation_seconds = 3599;
        assert!(matches!(
            validate_geometry(&workflow),
            Err(ArtifactCause::Identity)
        ));
        drop(requirements);
        drop(workflow);
        catalog.try_close().map_err(|_| "catalog close refused")?;
        decoder.try_close().map_err(|_| "decoder close refused")?;
        Ok(())
    }
}
