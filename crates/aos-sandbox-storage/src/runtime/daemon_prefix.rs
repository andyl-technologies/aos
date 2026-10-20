//! Fixed initial daemon prefixes under the same genuine Storage service payer.
//!
//! Native originals retain their own complete IO/parse posts. Successful normal
//! outputs move directly into the daemon's already resident outer destinations;
//! a marker never replaces the original native or credential failure.

use super::*;
use crate::operator_recovery_credentials::{
    StorageOperatorCredentialStartupV1, StorageOperatorRecoveryCredentialsV1,
};
use crate::process::StorageExecutorStartupV1;
use crate::storage_zfs_hold_key::{StorageZfsHoldKeyStartupV1, StorageZfsHoldKeyV1};
use aos_sandbox_core::{AccountingError, ResourceDimension as D, ResourceVector};

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum DaemonPrefixProfileV1 {
    Ordinary,
    HeldNative,
}

#[derive(Clone, Copy)]
enum Entry {
    HoldKey,
    Executor,
    Operator,
}

impl Entry {
    fn slot(self) -> usize {
        match self {
            Self::HoldKey => 0,
            Self::Executor => 1,
            Self::Operator => 2,
        }
    }
}

#[derive(Clone, Copy)]
enum Bookend {
    Before,
    After,
}

pub(super) struct StorageDaemonPrefixV1 {
    profile: Option<DaemonPrefixProfileV1>,
    demand: Option<Result<ResourceVector, AccountingError>>,
    output: crate::execution_output_credential::StorageExecutionOutputStartupV1,
    output_result: Option<Result<(), crate::service::StorageServiceError>>,
    key: StorageZfsHoldKeyStartupV1,
    executor: StorageExecutorStartupV1,
    operator: StorageOperatorCredentialStartupV1,
    before: [Option<Result<(), aos_sandbox::StorageReceivingClosedV1>>; 3],
    after: [Option<Result<(), aos_sandbox::StorageReceivingClosedV1>>; 3],
}

impl StorageDaemonPrefixV1 {
    pub(super) fn new() -> Self {
        Self {
            profile: None,
            demand: None,
            output: crate::execution_output_credential::StorageExecutionOutputStartupV1::new(),
            output_result: None,
            key: StorageZfsHoldKeyStartupV1::new(),
            executor: StorageExecutorStartupV1::new(),
            operator: StorageOperatorCredentialStartupV1::new(),
            before: [None, None, None],
            after: [None, None, None],
        }
    }

    fn demand(profile: DaemonPrefixProfileV1) -> Result<ResourceVector, AccountingError> {
        use crate::receiving_demand::{add, count};

        let invalid = || AccountingError::ArithmeticOverflow {
            dimension: D::MemoryBytes,
        };
        let executor = StorageExecutorStartupV1::receiving_memory_bytes()
            .ok_or_else(invalid)?;
        let operator = StorageOperatorCredentialStartupV1::receiving_memory_bytes()
            .ok_or_else(invalid)?;
        let mut memory = add(count(executor)?, count(operator)?)?;
        memory = add(memory, count(crate::helper::StorageSnapshotMetadataStartupV1::receiving_memory_bytes())?)?;
        let mut files = StorageExecutorStartupV1::receiving_open_files()
            + StorageOperatorCredentialStartupV1::receiving_open_files() + 2;
        let mut metadata = StorageExecutorStartupV1::receiving_metadata_entries()
            + StorageOperatorCredentialStartupV1::receiving_metadata_entries() + 8;
        if profile == DaemonPrefixProfileV1::HeldNative {
            memory = add(memory, count(
                StorageZfsHoldKeyStartupV1::receiving_memory_bytes().ok_or_else(invalid)?,
            )?)?;
            files += StorageZfsHoldKeyStartupV1::receiving_open_files();
            metadata += StorageZfsHoldKeyStartupV1::receiving_metadata_entries();
        }
        // The daemon's normal outputs remain simultaneously resident outside
        // their partial-read reservoirs until actual shared Runtime transfer.
        memory = add(memory, count(std::mem::size_of::<StorageOriginalNativeConstructionV1>()
            + std::mem::size_of::<StorageZfsHoldKeyV1>()
            + std::mem::size_of::<StorageOperatorRecoveryCredentialsV1>()
            + std::mem::size_of::<SystemdZfsExecutor>()
            + std::mem::size_of::<super::startup_assembly::StorageRuntimeAssemblyV1>())?)?;

        Ok(ResourceVector::ZERO
            .with(D::MemoryBytes, memory)
            .with(D::MetadataEntries, count(metadata)?)
            .with(D::OpenFiles, count(files)?))
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.demand.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &dyn std::error::Error)
            .or_else(|| self.output.failure())
            .or_else(|| self.output_result.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.key.failure())
            .or_else(|| self.executor.failure())
            .or_else(|| self.operator.failure())
    }

    pub(super) fn matches(&self, profile: DaemonPrefixProfileV1) -> bool {
        self.profile == Some(profile)
    }
}

impl StorageOriginalNativeConstructionV1 {
    /// Pays the ordinary measured daemon prefix before fixed native captures.
    ///
    /// # Errors
    ///
    /// Refuses a changed actual invocation/template, absent service original,
    /// reentry or conservative configuration/prefix demand that does not fit.
    pub fn prepare_ordinary_daemon_prefix_once_v1(
        &mut self,
        authority_directory: &Path,
        bootstrap_directory: &Path,
        resolver_policy_directory: Option<&Path>,
    ) -> Result<(), StorageOriginalNativeConstructionClosedV1> {
        self.prepare_daemon_prefix_once_v1(
            DaemonPrefixProfileV1::Ordinary,
            authority_directory,
            bootstrap_directory,
            resolver_policy_directory,
        )
    }

    /// Pays the held measured daemon prefix before key or executor capture.
    ///
    /// # Errors
    ///
    /// Refuses a different actual key-profile invocation, absent original,
    /// reentry or conservative configuration/prefix demand that does not fit.
    pub fn prepare_held_native_daemon_prefix_once_v1(
        &mut self,
        authority_directory: &Path,
        bootstrap_directory: &Path,
        resolver_policy_directory: Option<&Path>,
    ) -> Result<(), StorageOriginalNativeConstructionClosedV1> {
        self.prepare_daemon_prefix_once_v1(
            DaemonPrefixProfileV1::HeldNative,
            authority_directory,
            bootstrap_directory,
            resolver_policy_directory,
        )
    }

    fn prepare_daemon_prefix_once_v1(
        &mut self,
        profile: DaemonPrefixProfileV1,
        authority_directory: &Path,
        bootstrap_directory: &Path,
        resolver_policy_directory: Option<&Path>,
    ) -> Result<(), StorageOriginalNativeConstructionClosedV1> {
        if self.phase != OriginalNativeConstructionPhaseV1::Captured
            || self.daemon_prefix.demand.is_some()
            || self.startup_configuration_demand.is_some()
        {
            self.close_resident();
            return Err(StorageOriginalNativeConstructionClosedV1);
        }
        let _crossing = self.unwind_fence();
        self.daemon_prefix.demand = Some(StorageDaemonPrefixV1::demand(profile));
        self.startup_configuration_demand = Some(ProtectedStorageBootstrap::receiving_demand_v1()
            .and_then(|bootstrap| bootstrap.checked_add(storage_runtime_fixed_receiving_demand_v1()))
            .and_then(|bootstrap| match resolver_policy_directory {
                Some(_) => ProtectedStorageResolverPolicyDirectoryV1::receiving_demand_v1()
                    .and_then(|policy| bootstrap.checked_add(policy)),
                None => Ok(bootstrap),
            })
            .and_then(|configuration| match self.daemon_prefix.demand.as_ref() {
                Some(Ok(prefix)) => configuration.checked_add(*prefix),
                Some(Err(cause)) => Err(*cause),
                None => Err(AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes }),
            }));
        self.catalog_observer_demand = Some(
            crate::pin_worker_runtime::catalog_observation_receiving_demand_v1(),
        );
        let result = (|| {
            let configuration = self.startup_configuration_demand.as_ref()
                .and_then(|result| result.as_ref().ok()).copied()
                .ok_or(StorageOriginalNativeConstructionClosedV1)?;
            let observer = self.catalog_observer_demand.as_ref()
                .and_then(|result| result.as_ref().ok()).copied()
                .ok_or(StorageOriginalNativeConstructionClosedV1)?;
            let template = self.template_open.template()
                .ok_or(StorageOriginalNativeConstructionClosedV1)?;
            let startup = self.startup.as_mut()
                .ok_or(StorageOriginalNativeConstructionClosedV1)?;
            let mut receiving = startup.borrow_storage_prepare_receiving_v1()
                .map_err(|_| StorageOriginalNativeConstructionClosedV1)?;
            match profile {
                DaemonPrefixProfileV1::Ordinary => receiving.select_ordinary_startup_once_v1(),
                DaemonPrefixProfileV1::HeldNative => receiving.select_held_native_startup_once_v1(),
            }.map_err(|_| StorageOriginalNativeConstructionClosedV1)?;
            receiving.require_storage_authority_directory_v1(authority_directory)
                .map_err(|_| StorageOriginalNativeConstructionClosedV1)?;
            receiving.require_storage_startup_directories_v1(bootstrap_directory, resolver_policy_directory)
                .map_err(|_| StorageOriginalNativeConstructionClosedV1)?;
            receiving.require_guest_root_template_v1(template.root(), template.root_tree_digest())
                .map_err(|_| StorageOriginalNativeConstructionClosedV1)?;
            receiving.reserve_startup_configuration_once_v1(configuration)
                .map_err(|_| StorageOriginalNativeConstructionClosedV1)?;
            receiving.reserve_catalog_observer_peak_once_v1(observer)
                .map_err(|_| StorageOriginalNativeConstructionClosedV1)?;
            Ok(())
        })();
        if result.is_ok() {
            self.daemon_prefix.profile = Some(profile);
        } else {
            self.close_resident();
        }
        result
    }

    pub(super) fn require_daemon_prefix_paid_current_v1(
        &mut self,
    ) -> Result<(), StorageOriginalNativeConstructionClosedV1> {
        if self.daemon_prefix.profile.is_none() {
            return Err(StorageOriginalNativeConstructionClosedV1);
        }
        self.startup.as_mut().ok_or(StorageOriginalNativeConstructionClosedV1)?
            .borrow_storage_prepare_receiving_v1()
            .map_err(|_| StorageOriginalNativeConstructionClosedV1)?
            .require_startup_current_v1().map_err(|_| StorageOriginalNativeConstructionClosedV1)
    }

    fn daemon_prefix_current_v1(
        &mut self,
        entry: Entry,
        bookend: Bookend,
    ) -> Result<(), StorageOriginalNativeConstructionClosedV1> {
        if self.phase != OriginalNativeConstructionPhaseV1::Captured
            || self.daemon_prefix.profile.is_none()
        {
            self.close_resident();
            return Err(StorageOriginalNativeConstructionClosedV1);
        }
        let occupied = match bookend {
            Bookend::Before => self.daemon_prefix.before[entry.slot()].is_some(),
            Bookend::After => self.daemon_prefix.after[entry.slot()].is_some(),
        };
        if occupied {
            self.close_resident();
            return Err(StorageOriginalNativeConstructionClosedV1);
        }
        let result = self.startup.as_mut()
            .ok_or(aos_sandbox::StorageReceivingClosedV1)
            .and_then(|startup| startup.borrow_storage_prepare_receiving_v1()
                .map_err(|_| aos_sandbox::StorageReceivingClosedV1))
            .and_then(|mut receiving| receiving.require_startup_current_v1());
        let failed = result.is_err();
        let destination = match bookend {
            Bookend::Before => &mut self.daemon_prefix.before[entry.slot()],
            Bookend::After => &mut self.daemon_prefix.after[entry.slot()],
        };
        *destination = Some(result);
        if failed { Err(StorageOriginalNativeConstructionClosedV1) } else { Ok(()) }
    }

    /// Deposits genuine existing Output custody into the resident daemon slot.
    ///
    /// # Errors
    /// Refuses a missing paid measured prefix, changed source, replacement,
    /// actual retained native/decode/post failure or repeated opening. This
    /// never provisions an Output ledger or borrows a caller budget as proof.
    pub fn capture_daemon_output_once_v1(
        &mut self,
        source: &Path,
        destination: &mut Option<crate::execution_output_credential::StorageExecutionOutputCustodyV1>,
    ) -> Result<(), StorageOriginalNativeConstructionClosedV1> {
        if destination.is_some() || self.daemon_prefix.profile.is_none()
            || self.daemon_prefix.output_result.is_some()
            || self.phase != OriginalNativeConstructionPhaseV1::Captured
        {
            self.close_resident();
            return Err(StorageOriginalNativeConstructionClosedV1);
        }
        let _crossing = self.unwind_fence();
        let startup = self.startup.as_mut().ok_or(StorageOriginalNativeConstructionClosedV1)?;
        let mut receiving = startup.borrow_storage_prepare_receiving_v1()
            .map_err(|_| StorageOriginalNativeConstructionClosedV1)?;
        self.daemon_prefix.output_result = Some(self.daemon_prefix.output.open_once_v1(&mut receiving, source));
        drop(receiving);
        if !matches!(self.daemon_prefix.output_result, Some(Ok(()))) {
            self.close_resident();
            return Err(StorageOriginalNativeConstructionClosedV1);
        }
        let Some(custody) = self.daemon_prefix.output.take_once_v1() else {
            self.close_resident();
            return Err(StorageOriginalNativeConstructionClosedV1);
        };
        *destination = Some(custody);
        Ok(())
    }

    /// Deposits the fixed held-key owner into the daemon's resident destination.
    ///
    /// # Errors
    ///
    /// Refuses missing held-prefix payment, a nonempty destination, actual
    /// native/decode/post failure or reentry. Partial custody stays on this owner.
    pub fn capture_daemon_hold_key_once_v1(
        &mut self,
        destination: &mut Option<StorageZfsHoldKeyV1>,
    ) -> Result<(), StorageOriginalNativeConstructionClosedV1> {
        if !self.daemon_prefix.matches(DaemonPrefixProfileV1::HeldNative) || destination.is_some() {
            self.close_resident();
            return Err(StorageOriginalNativeConstructionClosedV1);
        }
        self.daemon_prefix_current_v1(Entry::HoldKey, Bookend::Before)?;
        let capture = self.daemon_prefix.key.capture_once();
        let post = self.daemon_prefix_current_v1(Entry::HoldKey, Bookend::After);
        if capture.is_err() || post.is_err() {
            self.close_resident();
            return Err(StorageOriginalNativeConstructionClosedV1);
        }
        let Some(key) = self.daemon_prefix.key.take_success() else {
            self.close_resident();
            return Err(StorageOriginalNativeConstructionClosedV1);
        };
        *destination = Some(key);
        Ok(())
    }

    /// Deposits the fixed executor into the daemon's resident destination.
    ///
    /// # Errors
    ///
    /// Refuses absent prefix payment, replacement of an existing output,
    /// actual partial cgroup/native failure or reentry.
    pub fn capture_daemon_executor_once_v1(
        &mut self,
        destination: &mut Option<SystemdZfsExecutor>,
    ) -> Result<(), StorageOriginalNativeConstructionClosedV1> {
        if destination.is_some() {
            self.close_resident();
            return Err(StorageOriginalNativeConstructionClosedV1);
        }
        self.daemon_prefix_current_v1(Entry::Executor, Bookend::Before)?;
        let capture = self.daemon_prefix.executor.capture_once();
        let post = self.daemon_prefix_current_v1(Entry::Executor, Bookend::After);
        if capture.is_err() || post.is_err() {
            self.close_resident();
            return Err(StorageOriginalNativeConstructionClosedV1);
        }
        let Some(executor) = self.daemon_prefix.executor.take_success() else {
            self.close_resident();
            return Err(StorageOriginalNativeConstructionClosedV1);
        };
        *destination = Some(executor);
        Ok(())
    }

    /// Deposits the fixed operator credentials into the resident destination.
    ///
    /// The actual daemon invokes this only when its inherited operator listener
    /// exists. The conservative prefix already pays that fixed optional peak.
    ///
    /// # Errors
    ///
    /// Refuses absent prefix payment, output replacement, native/role/decode
    /// failure or reentry. Every unsuccessful prefix remains on this owner.
    pub fn capture_daemon_operator_credentials_once_v1(
        &mut self,
        destination: &mut Option<StorageOperatorRecoveryCredentialsV1>,
    ) -> Result<(), StorageOriginalNativeConstructionClosedV1> {
        if destination.is_some() {
            self.close_resident();
            return Err(StorageOriginalNativeConstructionClosedV1);
        }
        self.daemon_prefix_current_v1(Entry::Operator, Bookend::Before)?;
        let capture = self.daemon_prefix.operator.capture_once();
        let post = self.daemon_prefix_current_v1(Entry::Operator, Bookend::After);
        if capture.is_err() || post.is_err() {
            self.close_resident();
            return Err(StorageOriginalNativeConstructionClosedV1);
        }
        let Some(credentials) = self.daemon_prefix.operator.take_success() else {
            self.close_resident();
            return Err(StorageOriginalNativeConstructionClosedV1);
        };
        *destination = Some(credentials);
        Ok(())
    }
}
