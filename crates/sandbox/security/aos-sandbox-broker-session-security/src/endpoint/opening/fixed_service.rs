//! Binds fixed Mount/Network broker acquisition to the real opening original.
//!
//! Both named entrances prepay the actual same loader and revalidation archive
//! before native capture. The existing take moves only the completed endpoint;
//! all earlier failed native prefixes remain on this opening owner.

use super::*;
use aos_sandbox_broker::receiving::{
    FixedServiceOperationClosedV4, MountServiceSessionOpeningLoanV4,
    NetworkServiceSessionOpeningLoanV4,
};
use aos_sandbox_model::{AccountingError, ResourceDimension as D, ResourceVector};

#[derive(Clone, Copy)]
enum First {
    Entry,
    Demand,
    Payment,
    Native,
    Protocol,
    Arming,
    Final,
}

pub(super) struct FixedServiceBrokerOpeningAdmissionV4 {
    entry: Option<Result<(), FixedServiceOperationClosedV4>>,
    demand: Option<Result<ResourceVector, AccountingError>>,
    payment: Option<Result<(), FixedServiceOperationClosedV4>>,
    protocol: Option<Result<(), BrokerSessionSecurityError>>,
    final_current: Option<Result<(), FixedServiceOperationClosedV4>>,
    first: Option<First>,
}

impl FixedServiceBrokerOpeningAdmissionV4 {
    const fn new() -> Self {
        Self {
            entry: None,
            demand: None,
            payment: None,
            protocol: None,
            final_current: None,
            first: None,
        }
    }

    pub(super) fn is_positive_v4(&self) -> bool {
        self.first.is_none()
            && matches!(self.entry, Some(Ok(())))
            && matches!(self.payment, Some(Ok(())))
            && matches!(self.protocol, Some(Ok(())))
            && matches!(self.final_current, Some(Ok(())))
    }
}

impl ProtectedBrokerSessionBrokerOpeningV1 {
    pub(crate) fn completed_transfer_shell_v1(&self) -> bool {
        self.completed.is_none() && self.inner.endpoint.is_none()
            && self.closed.is_none() && matches!(self.arming, Some(Ok(())))
            && self.fixed_service.as_ref().is_some_and(|original| original.is_positive_v4())
            && self.inner.failure().is_none()
    }

    /// Prices the actual retained fixed-role endpoint and revalidation archive.
    ///
    /// This DATA admits no role or file. The same named loader checks the
    /// genuine F before selecting this requirement and any native acquisition.
    ///
    /// # Errors
    /// Refuses checked layout, native reservoir or conversion overflow.
    pub(crate) fn fixed_service_receiving_demand_v4() -> Result<ResourceVector, AccountingError> {
        use aos_sandbox_linux::self_execution::{
            RetainedSelfExecutionGuard as Guard, SelfExecutionObservationV1 as Observation,
        };
        let overflow = || AccountingError::ArithmeticOverflow {
            dimension: D::MemoryBytes,
        };
        let archive = endpoint_revalidation_footprint_v1().ok_or_else(overflow)?;
        let memory = std::mem::size_of::<Self>()
            .checked_mul(2)
            .and_then(|bytes| {
                bytes.checked_add(ProtectedEndpointFilesOpeningV1::secret_heap_bytes_v1())
            })
            .and_then(|bytes| {
                bytes.checked_add(ProtectedEndpointFilesRevalidationV1::secret_heap_bytes_v1())
            })
            .and_then(|bytes| bytes.checked_add(Guard::selected_capture_heap_bytes_v1()))
            .and_then(|bytes| {
                bytes.checked_add(Observation::receiving_heap_bytes_v1().checked_mul(2)?)
            })
            .and_then(|bytes| bytes.checked_add(archive.inline_bytes))
            .and_then(|bytes| bytes.checked_add(archive.heap_bytes))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(overflow)?;
        let files = ProtectedEndpointFilesOpeningV1::opened_file_bound_v1()
            .checked_add(ProtectedEndpointFilesRevalidationV1::opened_file_bound_v1())
            .and_then(|files| files.checked_add(Guard::selected_capture_opened_file_bound_v1()))
            .and_then(|files| files.checked_add(Observation::opened_file_bound_v1()))
            .and_then(|files| files.checked_add(archive.file_descriptors))
            .and_then(|files| u64::try_from(files).ok())
            .ok_or(AccountingError::ArithmeticOverflow {
                dimension: D::OpenFiles,
            })?;
        // Fixed endpoint custody components/manifest/two local/two absent
        // opposite files and the same selected self proc/boot names. Repeated
        // native posts create no additional namespace entries or Rust fees.
        Ok(ResourceVector::ZERO
            .with(D::MemoryBytes, memory)
            .with(D::OpenFiles, files)
            .with(D::MetadataEntries, 19))
    }

    /// Captures only Mount's fixed Broker endpoint under its real opening loan.
    /// All returned native prefixes remain on this owner after refusal.
    pub(crate) fn load_mount_session_opening_once_v4(
        &mut self,
        loan: &mut MountServiceSessionOpeningLoanV4<'_>,
    ) {
        self.load_fixed_service_once_v4(FixedServiceBrokerRoleV4::Mount, &mut FixedServiceOpeningLoanV5::Fixed(loan));
    }

    /// Captures only Network's fixed Broker endpoint under its real opening loan.
    /// This delegates the same loader and retains the distinct original F.
    pub(crate) fn load_network_session_opening_once_v4(
        &mut self,
        loan: &mut NetworkServiceSessionOpeningLoanV4<'_>,
    ) {
        self.load_fixed_service_once_v4(FixedServiceBrokerRoleV4::Network, &mut FixedServiceOpeningLoanV5::Fixed(loan));
    }

    /// Captures Host's same fixed endpoint under its actual current-Control loan.
    pub(crate) fn load_host_cleanup_session_opening_once_v1(
        &mut self, loan: &mut aos_sandbox_host::HostControlColdSessionLoanV1<'_>,
    ) {
        self.load_fixed_service_once_v4(FixedServiceBrokerRoleV4::Host,
            &mut FixedServiceOpeningLoanV5::Host(loan));
    }

    fn load_fixed_service_once_v4(
        &mut self,
        role: FixedServiceBrokerRoleV4,
        loan: &mut FixedServiceOpeningLoanV5<'_, '_>,
    ) {
        if self.fixed_service.is_some()
            || self.inner.native_entered
            || self.completed.is_some()
            || self.arming.is_some()
            || self.closed.is_some()
        {
            self.closed
                .get_or_insert(BrokerSessionSecurityError::Currentness);
            return;
        }
        self.fixed_service = Some(FixedServiceBrokerOpeningAdmissionV4::new());
        self.load_fixed_service_body_v4(role, loan);
    }

    fn load_fixed_service_body_v4(
        &mut self,
        role: FixedServiceBrokerRoleV4,
        loan: &mut FixedServiceOpeningLoanV5<'_, '_>,
    ) {
        let Some(original) = self.fixed_service.as_mut() else {
            std::process::abort();
        };
        original.entry = Some(role.require_current(loan));
        if !matches!(original.entry, Some(Ok(()))) {
            original.first = Some(First::Entry);
            return;
        }
        original.demand = Some(Self::fixed_service_receiving_demand_v4());
        let Some(Ok(demand)) = original.demand.as_ref().copied() else {
            original.first = Some(First::Demand);
            return;
        };
        original.payment = Some(loan.require_additional_representation_v4(demand));
        if !matches!(original.payment, Some(Ok(()))) {
            original.first = Some(First::Payment);
            return;
        }

        // This is the same selected loader used by the existing Storage and
        // Controller paths: actual files/entropy and independent native posts
        // are parked inside it before the next fallible step.
        self.inner.load_native_once(
            Path::new(role.custody()),
            EndpointRole::Broker,
            &mut KernelEntropy,
        );
        self.completed = self
            .inner
            .endpoint
            .take()
            .map(|inner| ProtectedBrokerSessionBrokerV1 { inner });
        let Some(completed) = self.completed.as_mut() else {
            original.first = Some(First::Native);
            return;
        };
        original.protocol = Some(
            if completed.protected_protocol_and_node().0 == role.protocol() {
                Ok(())
            } else {
                Err(BrokerSessionSecurityError::Currentness)
            },
        );
        if !matches!(original.protocol, Some(Ok(()))) {
            original.first = Some(First::Protocol);
            return;
        }
        self.arming = Some(completed.arm_fixed_service_revalidation_once_v4(role, loan));
        if !matches!(self.arming, Some(Ok(()))) {
            original.first = Some(First::Arming);
            return;
        }
        original.final_current = Some(role.require_current(loan));
        if !matches!(original.final_current, Some(Ok(()))) {
            original.first = Some(First::Final);
        }
    }

    /// Selects only the chronological refusal held by the genuine F original.
    /// This diagnostic comparison performs no IO and admits no operation.
    pub(crate) fn fixed_service_original_failure_selected_v4(&self) -> bool {
        self.fixed_service_failure_v4()
            .is_some_and(|cause| cause.is::<FixedServiceOperationClosedV4>())
    }

    pub(super) fn fixed_service_failure_v4(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let original = self.fixed_service.as_ref()?;
        match original.first? {
            First::Entry => original
                .entry
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::Demand => original
                .demand
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::Payment => original
                .payment
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::Native => self.inner.failure(),
            First::Protocol => original
                .protocol
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::Arming => self
                .completed
                .as_ref()
                .and_then(|endpoint| endpoint.retained_revalidation_failure())
                .or_else(|| self.arming.as_ref()?.as_ref().err().map(|cause| cause as _)),
            First::Final => original
                .final_current
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
        }
    }
}
