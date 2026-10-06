//! Configuration copies admitted by the original artifact resource owner.
//!
//! Owning strings, paths, trees and replay plans receive independent credits
//! before copying. Shared service handles retain their existing authority.

use super::*;
use crucible::owned_decode::{
    DecodeAdmissionError, charge_array, charge_btree_entry, current_child_budget, current_custody,
};
use crucible_protocol::app_random_branch_plan::{
    AppRandomBranchPlan, AppRandomBranchPlanEntry, AppRandomBranchPlanError,
};

#[cfg(any(test, feature = "test-support"))]
mod tests;

#[cfg(test)]
pub(super) fn copy_component_configuration(
    source: &ProductionVmLifecycleConfig,
) -> Arc<ProductionVmLifecycleConfig> {
    tests::copy_component_configuration(source)
}

#[cfg(any(test, feature = "test-support"))]
pub(super) fn component_assertion_evaluator(source: &ScenarioDefForm) -> HostAssertionEvaluator {
    let budget = tests::component_decode_budget();
    let _scope = budget.enter();
    HostAssertionEvaluator::new(source.properties())
        .and_then(|evaluator| evaluator.with_world_white_box_policies(source.world()))
        .unwrap_or_else(|error| panic!("finite component assertion evaluator: {error}"))
}

/// A refusal to copy lifecycle configuration under its original resource owner.
#[derive(Debug, thiserror::Error)]
pub enum ProductionVmLifecycleConfigCloneError {
    /// No original input resource account is installed for this copy.
    #[error("lifecycle configuration copy requires original input resource authority")]
    MissingAdmission,
    /// Original resource admission or fallible allocation refused the copy.
    #[error("lifecycle configuration allocation refused: {0}")]
    Admission(#[from] DecodeAdmissionError),
    /// A canonical model member could not be copied under the same account.
    #[error("lifecycle model copy refused: {0}")]
    Model(#[source] Box<crucible::EngineError>),
    /// A selectable replay plan could not be copied under the same account.
    #[error("lifecycle signal replay copy refused: {0}")]
    Signal(#[source] Box<crucible::SignalFaultSelectableError>),
    /// An app-random plan failed its canonical invariant checks.
    #[error("lifecycle app-random plan copy refused: {0}")]
    AppRandom(#[from] AppRandomBranchPlanError),
    /// A resolved replay trace could not be copied under the same account.
    #[error("lifecycle resolved replay copy refused: {0}")]
    Replay(#[source] DecodeAdmissionError),
    /// A copied diagnostic retains the failed copy's original allocation credit.
    #[error("{source}")]
    Retained {
        /// Original typed copy refusal, preserved without a string conversion.
        #[source]
        source: Arc<ProductionVmLifecycleConfigCloneError>,
        /// Actual original-owner credits for diagnostic and partial-copy storage.
        custody: crucible::owned_decode::DecodeCustody,
    },
}

impl From<ProductionVmLifecycleConfigCloneError> for LifecycleApiError {
    fn from(error: ProductionVmLifecycleConfigCloneError) -> Self {
        Self::ConfigurationCopy(DecodeAdmissionError::new(error))
    }
}

impl ProductionVmLifecycleConfig {
    /// Copies owning configuration members under the original input account.
    ///
    /// Every copied allocation receives independent credit before allocation.
    /// The result retains that account through lifecycle and world cleanup;
    /// service handles and immutable artifact stores share their original owners.
    /// Fixed storage for one immediate `Arc` installation is admitted too, so
    /// a factory can move this copy into shared ownership without another loan.
    ///
    /// # Errors
    /// Refuses a missing original account, exhausted authority, allocation
    /// failure, or invalid canonical replay members before publishing the copy.
    pub fn try_clone_admitted(&self) -> Result<Self, ProductionVmLifecycleConfigCloneError> {
        let _retained_scope = if current_custody().is_none() {
            self.enter_input_custody()
        } else {
            None
        };
        let child = current_child_budget()?
            .ok_or(ProductionVmLifecycleConfigCloneError::MissingAdmission)?;
        let _copy_scope = child.enter();
        charge_array::<Self>(1)?;
        charge_array::<usize>(2)?;
        self.copy_under_current_account()
    }

    fn copy_under_current_account(&self) -> Result<Self, ProductionVmLifecycleConfigCloneError> {
        let decode_custody =
            current_custody().ok_or(ProductionVmLifecycleConfigCloneError::MissingAdmission)?;
        // A later copy refusal may need one typed model-error box. Admit its
        // fixed storage before any data copy can exhaust the original account.
        let diagnostic_bytes = std::mem::size_of::<crucible::EngineError>()
            .max(std::mem::size_of::<crucible::SignalFaultSelectableError>());
        charge_array::<u8>(diagnostic_bytes)?;
        charge_array::<ProductionVmLifecycleConfigCloneError>(3)?;
        charge_array::<usize>(4)?;
        let failure_custody = decode_custody.clone();

        let result = (|| {
            Ok(Self {
                decode_custody: Some(decode_custody),
                host_ram_registration_factory: self.host_ram_registration_factory.clone(),
                ram_catalog_provider: self.ram_catalog_provider.clone(),
                #[cfg(any(test, feature = "test-support"))]
                ram_source_decorator: self.ram_source_decorator.clone(),
                #[cfg(any(test, feature = "test-support"))]
                block_completion_observer: self.block_completion_observer.clone(),
                #[cfg(any(test, feature = "test-support"))]
                fault_actor_test_entitlement: self.fault_actor_test_entitlement,
                executable: copy_path(&self.executable)?,
                plugin: copy_path(&self.plugin)?,
                native_guest_architecture: self.native_guest_architecture,
                guest_assets: copy_map(&self.guest_assets, |key, value| {
                    Ok((
                        *key,
                        ProductionVmGuestAssets {
                            kernel: copy_path(&value.kernel)?,
                            root_image: copy_path(&value.root_image)?,
                            kernel_cmdline_prefix: copy_option(
                                &value.kernel_cmdline_prefix,
                                |text| copy_string(text),
                            )?,
                        },
                    ))
                })?,
                initrd: copy_option(&self.initrd, |path| copy_path(path))?,
                kernel_cmdline_prefix: copy_option(&self.kernel_cmdline_prefix, |text| {
                    copy_string(text)
                })?,
                root_image_format: self.root_image_format,
                run_state_root: copy_path(&self.run_state_root)?,
                run_ceiling_ticks: self.run_ceiling_ticks,
                quantum_budget: self.quantum_budget,
                maximum_host_workers: self.maximum_host_workers,
                rendezvous_interval_ticks: self.rendezvous_interval_ticks,
                completion_timeout: self.completion_timeout,
                host_operation_supervisor: self.host_operation_supervisor.clone(),
                unbounded_advance_completion: self.unbounded_advance_completion,
                coverage: self.coverage,
                rr_control_boundary_trace: self.rr_control_boundary_trace,
                debug_gateway_executable: copy_option(&self.debug_gateway_executable, |path| {
                    copy_path(path)
                })?,
                debug: copy_option(&self.debug, copy_debug)?,
                branch: copy_option(&self.branch, copy_branch)?,
                continuation_branches: copy_vec(&self.continuation_branches, copy_branch)?,
                signal_fault_replay: copy_option(&self.signal_fault_replay, |plan| {
                    plan.try_clone_admitted().map_err(|error| {
                        ProductionVmLifecycleConfigCloneError::Signal(Box::new(error))
                    })
                })?,
                branch_network_choices: copy_vec(&self.branch_network_choices, copy_selection)?,
                app_random_branch_selections: copy_map(
                    &self.app_random_branch_selections,
                    |key, value| Ok((*key, copy_selection(value)?)),
                )?,
                app_random_branch_plans: copy_map(&self.app_random_branch_plans, |key, value| {
                    Ok((
                        NodeId {
                            name: copy_string(&key.name)?,
                        },
                        copy_app_random(value)?,
                    ))
                })?,
                signal_artifacts: self.signal_artifacts.clone(),
                fault_replay: copy_option(&self.fault_replay, |trace| {
                    trace
                        .try_clone_admitted()
                        .map_err(ProductionVmLifecycleConfigCloneError::Replay)
                })?,
                world_artifacts: self.world_artifacts.clone(),
                bounded_scheduler_preemption: self.bounded_scheduler_preemption.clone(),
            })
        })();
        result.map_err(|source| ProductionVmLifecycleConfigCloneError::Retained {
            source: Arc::new(source),
            custody: failure_custody,
        })
    }

    /// Enters the resource account retained by an admitted configuration copy.
    ///
    /// Constructors for operator-authored configuration have no artifact
    /// account. Their launch caller must supply its accepted original scope.
    #[must_use]
    pub fn enter_input_custody(&self) -> Option<crucible::owned_decode::DecodeScope> {
        self.decode_custody
            .as_ref()
            .and_then(|custody| custody.enter())
    }

    /// Copies configuration into independently admitted shared owning storage.
    ///
    /// Later `Arc` clones share this copy and its original account without
    /// allocating another configuration or replay payload.
    ///
    /// # Errors
    /// Refuses a missing original account, insufficient control-block or copy
    /// credits, allocation failure, or invalid canonical replay members.
    pub fn try_clone_shared_admitted(
        &self,
    ) -> Result<Arc<Self>, ProductionVmLifecycleConfigCloneError> {
        let _retained_scope = if current_custody().is_none() {
            self.enter_input_custody()
        } else {
            None
        };
        let child = current_child_budget()?
            .ok_or(ProductionVmLifecycleConfigCloneError::MissingAdmission)?;
        let _copy_scope = child.enter();
        charge_array::<Self>(1)?;
        charge_array::<usize>(2)?;
        Ok(Arc::new(self.copy_under_current_account()?))
    }
}

fn copy_string(value: &str) -> Result<String, ProductionVmLifecycleConfigCloneError> {
    charge_array::<u8>(value.len())?;
    let mut result = String::new();
    result
        .try_reserve_exact(value.len())
        .map_err(DecodeAdmissionError::new)?;
    result.push_str(value);
    Ok(result)
}

fn copy_path(value: &Path) -> Result<PathBuf, ProductionVmLifecycleConfigCloneError> {
    let source = value.as_os_str();
    charge_array::<u8>(source.as_encoded_bytes().len())?;
    let mut result = std::ffi::OsString::new();
    result
        .try_reserve_exact(source.as_encoded_bytes().len())
        .map_err(DecodeAdmissionError::new)?;
    result.push(source);
    Ok(result.into())
}

fn copy_option<T, U>(
    value: &Option<T>,
    copy: impl FnOnce(&T) -> Result<U, ProductionVmLifecycleConfigCloneError>,
) -> Result<Option<U>, ProductionVmLifecycleConfigCloneError> {
    value.as_ref().map(copy).transpose()
}

fn copy_vec<T, U>(
    values: &[T],
    mut copy: impl FnMut(&T) -> Result<U, ProductionVmLifecycleConfigCloneError>,
) -> Result<Vec<U>, ProductionVmLifecycleConfigCloneError> {
    charge_array::<U>(values.len())?;
    let mut result = Vec::new();
    result
        .try_reserve_exact(values.len())
        .map_err(DecodeAdmissionError::new)?;
    for value in values {
        result.push(copy(value)?);
    }
    Ok(result)
}

fn copy_map<K: Ord, V>(
    values: &BTreeMap<K, V>,
    mut copy: impl FnMut(&K, &V) -> Result<(K, V), ProductionVmLifecycleConfigCloneError>,
) -> Result<BTreeMap<K, V>, ProductionVmLifecycleConfigCloneError> {
    let mut result = BTreeMap::new();
    for (key, value) in values {
        charge_btree_entry::<K, V>()?;
        let (key, value) = copy(key, value)?;
        result.insert(key, value);
    }
    Ok(result)
}

fn copy_debug(
    value: &ProductionVmDebugConfig,
) -> Result<ProductionVmDebugConfig, ProductionVmLifecycleConfigCloneError> {
    Ok(ProductionVmDebugConfig {
        node: copy_option(&value.node, |node| copy_string(node))?,
        operator_listen: copy_string(&value.operator_listen)?,
        all_nodes: value.all_nodes,
        allow_requested_loopback_listen: value.allow_requested_loopback_listen,
    })
}

fn copy_branch(
    value: &ProductionVmBranchConfig,
) -> Result<ProductionVmBranchConfig, ProductionVmLifecycleConfigCloneError> {
    Ok(ProductionVmBranchConfig {
        base: value
            .base
            .try_clone_admitted()
            .map_err(|error| ProductionVmLifecycleConfigCloneError::Model(Box::new(error)))?,
        frontier: value.frontier,
        seed: value.seed,
    })
}

fn copy_selection(
    value: &crucible::SelectionDecision,
) -> Result<crucible::SelectionDecision, ProductionVmLifecycleConfigCloneError> {
    value
        .try_clone_admitted()
        .map_err(|error| ProductionVmLifecycleConfigCloneError::Model(Box::new(error)))
}

fn copy_app_random(
    value: &AppRandomBranchPlan,
) -> Result<AppRandomBranchPlan, ProductionVmLifecycleConfigCloneError> {
    let entries = copy_vec(value.entries(), |entry| {
        Ok(AppRandomBranchPlanEntry::new(
            entry.draw_index(),
            entry.expected_raw_value(),
            entry.selected_value(),
            entry.selection_id(),
            copy_string(entry.stream_name())?,
        )?)
    })?;
    Ok(AppRandomBranchPlan::new(entries)?)
}
