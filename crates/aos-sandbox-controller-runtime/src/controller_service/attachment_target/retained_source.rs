//! Keeps the existing trusted attachment input and Host observation pipeline.
//!
//! This is a one-shot native destination. The actual C18 caller prepays its
//! fixed demand, then the reached journal/model demand before replay. Nothing
//! here reserves resources or supplies a new assignment/proof constructor.

use super::*;
use aos_sandbox_core::BrokerPlanTrustAnchor;
use aos_sandbox_linux::cgroup::RuntimeScopeCgroupOriginalV1;
use aos_sandbox::runtime_scope::{RuntimeScopeOpeningOriginalV1, RuntimeScopeAcquireOriginalV1};
use super::super::credential_receiving::CredentialAttemptV1;

type OwnershipAttempt = CredentialAttemptV1<ControllerOwnershipConfigurationV1, ControllerOwnershipCredentialErrorV1>;
type AnchorAttempt = CredentialAttemptV1<BrokerPlanTrustAnchor, ControllerBrokerPlanSignerError>;

pub(crate) struct ControllerAttachmentSourceOriginalV1 {
    cgroup_admission: RuntimeScopeCgroupOriginalV1,
    cgroup_root: Option<CgroupV2Root>,
    cgroup: Option<RetainedCgroupAnchor>,
    ownership_credentials: OwnershipAttempt,
    broker_credentials: AnchorAttempt,
    mount_credentials: AnchorAttempt,
    ownership: Option<ControllerOwnershipConfigurationV1>,
    broker_anchor: Option<BrokerPlanTrustAnchor>,
    mount_broker_anchor: Option<BrokerPlanTrustAnchor>,
    pub(super) inputs: Option<ControllerAttachmentTargetInputsV1>,
    pub(super) opening: RuntimeScopeOpeningOriginalV1,
    pub(super) client: Option<RuntimeScopeClient>,
    pub(super) policy: Option<CurrentRuntimeScopePolicy>,
    pub(super) acquisition: RuntimeScopeAcquireOriginalV1,
    configuration: Option<Result<(), ControllerAttachmentProvisionErrorV1>>,
    prepared: Option<ControllerAttachmentTargetInputsV1>,
    result: Option<Result<CurrentRuntimeScope, ControllerAttachmentTargetErrorV1>>,
    attempted: bool,
    taken: bool,
}

impl ControllerAttachmentSourceOriginalV1 {
    /// Creates empty destinations without native IO or credential allocation.
    pub(crate) fn new() -> Self {
        Self {
            cgroup_admission: RuntimeScopeCgroupOriginalV1::new(),
            cgroup_root: None,
            cgroup: None,
            ownership_credentials: CredentialAttemptV1::new(),
            broker_credentials: CredentialAttemptV1::new(),
            mount_credentials: CredentialAttemptV1::new(),
            ownership: None,
            broker_anchor: None,
            mount_broker_anchor: None,
            inputs: None,
            opening: RuntimeScopeOpeningOriginalV1::new(),
            client: None,
            policy: None,
            acquisition: RuntimeScopeAcquireOriginalV1::new(),
            configuration: None,
            prepared: None,
            result: None,
            attempted: false,
            taken: false,
        }
    }

    /// Returns this native/credential pipeline's fixed complete representation.
    ///
    /// The actual C18 caller separately prepays reached protected-journal and
    /// signed-artifact model debt before their existing engines allocate. The
    /// directory is the actual already-held trusted startup locator, not a
    /// caller-selected alternate credential authority.
    pub(crate) fn fixed_receiving_demand_v1(
        _host: &HostServiceIdentity,
        credential_directory: &std::ffi::OsStr,
    ) -> Option<aos_sandbox_core::ResourceVector> {
        use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
        use aos_sandbox_core::format::TrustPolicyDecodeCaptureV1;
        use aos_sandbox_linux::credential::FixedRoleCredentialReadV1;
        use aos_sandbox_ownership_protocol::trusted_policy::OwnershipTrustConfigurationCaptureV1;
        use std::os::unix::ffi::OsStrExt as _;
        let host_policy = aos_sandbox_protocol::authorization_artifact::SigningAuthority::maximum_canonical_policy_bytes_v1();
        let ownership_policy = 64 * 1024;
        let directory_bytes = credential_directory.as_bytes().len();
        let joined_paths = FixedRoleCredentialReadV1::joined_path_receiving_bytes_for_lengths_v1(
            directory_bytes, "mount-broker-plan-policy.cbor".len(),
        )?;
        // Three retained reader inputs plus each shared constructor's current
        // directory copy and recorded locator; one current joined-path peak.
        let paths = directory_bytes.checked_mul(10)?.checked_add(joined_paths)?;
        let ownership = OwnershipTrustConfigurationCaptureV1::receiving_memory_bytes_v1(ownership_policy)?;
        let anchor = TrustPolicyDecodeCaptureV1::receiving_carrier_bytes_v1(host_policy)?
            .checked_mul(2)?.checked_add(host_policy.checked_mul(8)?)?
            .checked_add(std::mem::size_of::<BrokerPlanTrustAnchor>().checked_mul(3)?)?;
        let credential_bytes = ownership_policy.checked_add(host_policy.checked_mul(2)?)?
            .checked_mul(3)?.checked_add(4 * 32 + 2 * 16)?;
        let (cgroup_bytes, cgroup_files, cgroup_names) = RuntimeScopeCgroupOriginalV1::receiving_demand_v1()?;
        let bytes = std::mem::size_of::<Self>().checked_mul(3)?
            .checked_add(paths)?.checked_add(ownership)?.checked_add(anchor.checked_mul(2)?)?
            .checked_add(credential_bytes)?.checked_add(cgroup_bytes)?;
        // Actual directory components, the nine fixed credential leaves and
        // the cgroup recipe's named objects bound filesystem namespace entries.
        // Policy/parser Vecs and their controls belong only to MemoryBytes.
        let entries = Path::new(credential_directory).components().count()
            .checked_add(9)?.checked_add(cgroup_names)?;
        RuntimeScopeAcquireOriginalV1::fixed_native_receiving_demand_v1()?.checked_add(
            ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?)
                .with(D::OpenFiles, u64::try_from(cgroup_files.checked_add(6)?).ok()?)
                .with(D::MetadataEntries, u64::try_from(entries).ok()?)
        ).ok()
    }

    /// Prepares only the fixed-funded trusted inputs from the real startup locator.
    ///
    /// The caller has consumed its same genuine C18 flight before entry. This
    /// runs the existing cgroup/credential constructors, but no Journal replay
    /// or Host scope exchange. Reentry preserves the first actual result.
    pub(crate) fn prepare_configuration_once(
        &mut self,
        host: &HostServiceIdentity,
        node: NodeId,
        credential_directory: &std::ffi::OsStr,
    ) {
        if self.configuration.is_some() || self.attempted {
            return;
        }
        if !self.ownership_credentials.bind_process_directory_once(credential_directory)
            || !self.broker_credentials.bind_process_directory_once(credential_directory)
            || !self.mount_credentials.bind_process_directory_once(credential_directory)
        {
            std::process::abort();
        }
        self.configuration = Some(match ControllerAttachmentTargetInputsV1::from_configuration_with_disposition(
            host, node, Some(&mut *self),
        ) {
            Ok(inputs) => {
                self.prepared = Some(inputs);
                Ok(())
            }
            Err(cause) => Err(cause),
        });
    }

    /// Derives the complete decoder/model peak from actual held rows and saved policy.
    ///
    /// This borrows DATA without parsing, allocating or performing IO. The
    /// caller checks it together with the still-held fixed prefix against its
    /// SAME genuine consumed C18 bound before capture_prepared_source_once.
    pub(crate) fn acquisition_receiving_demand_v1(
        &self,
        journal: &Journal,
    ) -> Option<aos_sandbox_core::ResourceVector> {
        if !matches!(self.configuration, Some(Ok(()))) || self.attempted {
            return None;
        }
        let inputs = self.prepared.as_ref()?;
        aos_sandbox::runtime_scope::current_source_receiving_demand_v1(journal, &inputs.policy)
    }

    /// Runs the same protected current-holder and Host exchange after model precharge.
    ///
    /// This private trusted-coordinator step creates no new readiness factory.
    /// Only the existing original assignment/signature/native engine constructs
    /// the returned CurrentRuntimeScope, and every failed prefix stays here.
    pub(crate) fn capture_prepared_source_once(&mut self, journal: &mut Journal, sandbox: SandboxId) {
        if self.attempted {
            return;
        }
        self.attempted = true;
        if !matches!(self.configuration, Some(Ok(()))) {
            return;
        }
        let Some(inputs) = self.prepared.take() else {
            return;
        };
        self.result = Some(inputs.acquire_source_with_disposition(journal, sandbox, Some(&mut *self)));
    }

    /// Borrows the exact completed existing native scope without admitting work.
    pub(crate) fn completed(&self) -> Option<&CurrentRuntimeScope> {
        self.result.as_ref()?.as_ref().ok()
    }

    /// Moves the same existing scope once after the entire acquisition succeeded.
    pub(crate) fn take_completed_once(&mut self) -> Option<CurrentRuntimeScope> {
        if self.taken || !matches!(self.result, Some(Ok(_))) {
            return None;
        }
        self.taken = true;
        match self.result.take()? {
            Ok(value) => Some(value),
            Err(_) => std::process::abort(),
        }
    }

    /// Borrows the earliest reached original cause, including native failed prefixes.
    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.cgroup_admission.failure().map(|cause| cause as _)
            .or_else(|| self.ownership_credentials.failure())
            .or_else(|| self.broker_credentials.failure())
            .or_else(|| self.mount_credentials.failure())
            .or_else(|| self.configuration.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.opening.failure())
            .or_else(|| self.acquisition.failure())
            .or_else(|| self.result.as_ref()?.as_ref().err().map(|cause| cause as _))
    }
}

// This finite adapter selects I/O custody only; both dispositions execute the
// same input/currentness engine. It carries no payer or completion callback.
pub(super) struct InputDestinationsV1<'a> {
    pub(super) cgroup_admission: Option<&'a mut RuntimeScopeCgroupOriginalV1>,
    pub(super) cgroup_root: Option<&'a mut Option<CgroupV2Root>>,
    pub(super) cgroup: Option<&'a mut Option<RetainedCgroupAnchor>>,
    pub(super) ownership_credentials: Option<&'a mut OwnershipAttempt>,
    pub(super) broker_credentials: Option<&'a mut AnchorAttempt>,
    pub(super) mount_credentials: Option<&'a mut AnchorAttempt>,
    pub(super) ownership: Option<&'a mut Option<ControllerOwnershipConfigurationV1>>,
    pub(super) broker_anchor: Option<&'a mut Option<BrokerPlanTrustAnchor>>,
    pub(super) mount_broker_anchor: Option<&'a mut Option<BrokerPlanTrustAnchor>>,
}

impl<'a> InputDestinationsV1<'a> {
    pub(super) fn new(original: Option<&'a mut ControllerAttachmentSourceOriginalV1>) -> Self {
        match original {
            Some(original) => Self {
                cgroup_admission: Some(&mut original.cgroup_admission),
                cgroup_root: Some(&mut original.cgroup_root),
                cgroup: Some(&mut original.cgroup),
                ownership_credentials: Some(&mut original.ownership_credentials),
                broker_credentials: Some(&mut original.broker_credentials),
                mount_credentials: Some(&mut original.mount_credentials),
                ownership: Some(&mut original.ownership),
                broker_anchor: Some(&mut original.broker_anchor),
                mount_broker_anchor: Some(&mut original.mount_broker_anchor),
            },
            None => Self {
                cgroup_admission: None,
                cgroup_root: None,
                cgroup: None,
                ownership_credentials: None,
                broker_credentials: None,
                mount_credentials: None,
                ownership: None,
                broker_anchor: None,
                mount_broker_anchor: None,
            },
        }
    }
}

pub(super) struct HeldInputV1<'a, T> {
    value: Option<T>,
    destination: Option<&'a mut Option<T>>,
}

impl<'a, T> HeldInputV1<'a, T> {
    pub(super) fn new(value: T, destination: Option<&'a mut Option<T>>) -> Self { Self { value: Some(value), destination } }
    pub(super) fn get(&self) -> Option<&T> {
        self.value.as_ref()
    }
    pub(super) fn take(mut self) -> Option<T> {
        self.value.take()
    }
}

impl<T> Drop for HeldInputV1<'_, T> {
    fn drop(&mut self) {
        if let Some(destination) = self.destination.as_deref_mut() {
            if self.value.is_some() {
                if destination.is_some() {
                    std::process::abort();
                }
                *destination = self.value.take();
            }
        }
    }
}
