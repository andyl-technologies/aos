//! Owns the image-enrolled Mount attachment service and every startup prefix.
//!
//! This purpose uses the existing Mount state and broker Session journals and
//! the sole destination Store constructor. It starts no helper or alternate
//! worker and cannot borrow the provider-Acquire, Controller or Root budgets.

mod startup;
mod callsite;
mod effect;
mod inventory;
mod cold;
pub use callsite::{MountServiceDomainCallsiteV4, MountServiceObservationV4};
pub use effect::MountServiceEffectOriginalV4;
pub use inventory::MountServiceInventoryOriginalV4;
pub use cold::MountServiceSessionInputsV4;

use std::error::Error;

use aos_sandbox_controller_domain::journal::MountBrokerSessionCapturedJournalOpenV4;

use aos_sandbox_mount_native::{MountJournalV1 as Journal, MountJournalErrorV1 as JournalError, MountStateCapturedJournalOpenV4, RecoveryReport};
use aos_sandbox_broker::{ProtectedBrokerAuthorityConfiguration,
    ProtectedBrokerPublicCredentials, ProtectedMountBrokerConfigurationOriginalV4, BrokerAuthorityConfigError};
use aos_sandbox_broker::receiving::{FixedServiceListenerOriginalV4,
    FixedServiceOperationClosedV4 as Closed, FixedServiceReceivingCaptureV1};
use aos_sandbox_model::{AccountingError, ResourceVector};

use crate::authorization::MountAuthorityV1;
use crate::destination_slot::{DestinationSlotStartupOriginalV4, DestinationSlotStoreV1};
use crate::{MountError, Result};

#[derive(Clone, Copy)]
enum Failure { Entrance, Geometry, Funding, Before, Configuration, State, Store, After, Transfer, Order }

/// Retains the actual fixed-role startup, authority, journals and namespace Store.
///
/// Construction is inert. Its actual PID1/image/profile/F3 entrance authenticates
/// and prices this compiled whole owner before subsequent native/model growth.
/// Negative owners remain resident; no readiness follows from its empty fields.
#[must_use]
pub struct MountAttachmentAnchorServiceOriginalV4 {
    common: FixedServiceReceivingCaptureV1<Closed>,
    configuration: ProtectedMountBrokerConfigurationOriginalV4,
    state_opening: MountStateCapturedJournalOpenV4,
    session_opening: MountBrokerSessionCapturedJournalOpenV4,
    store_opening: DestinationSlotStartupOriginalV4,
    listener_opening: FixedServiceListenerOriginalV4,
    state: Option<Journal>,
    state_report: Option<RecoveryReport>,
    authority: Option<MountAuthorityV1>,
    credentials: Option<ProtectedBrokerPublicCredentials>,
    store: Option<DestinationSlotStoreV1>,
    runtime_layout: Option<std::result::Result<usize, AccountingError>>,
    fixed: Option<std::result::Result<ResourceVector, MountServiceGeometryErrorV4>>,
    state_extent: Option<std::result::Result<ResourceVector, MountServiceGeometryErrorV4>>,
    store_extent: Option<Result<ResourceVector>>,
    admitted: ResourceVector,
    growth: Option<std::result::Result<ResourceVector, AccountingError>>,
    callsite_geometry: Option<std::result::Result<ResourceVector, AccountingError>>,
    startup: Option<Result<()>>,
    startup_body: Option<Result<()>>,
    startup_after: Option<std::result::Result<(), Closed>>,
    funding: [Option<std::result::Result<(), Closed>>; 3],
    entrance: Option<std::result::Result<(), Closed>>,
    native_before: Option<std::result::Result<(), Closed>>,
    configuration_result: Option<std::result::Result<(), BrokerAuthorityConfigError>>,
    store_result: Option<Result<()>>,
    listener_result: Option<std::result::Result<(), Closed>>,
    entered: bool,
    ready: bool,
    cold_borrowed: bool,
    first: Option<Failure>,
    closed: Closed,
}

impl Default for MountAttachmentAnchorServiceOriginalV4 {
    fn default() -> Self { Self::new() }
}

impl MountAttachmentAnchorServiceOriginalV4 {
    /// Creates only the compiled empty receiving/native destinations.
    #[must_use]
    pub fn new() -> Self {
        Self::with_runtime_layout(std::mem::size_of::<Self>())
    }

    /// Prices the actual enclosing runtime header at the first native entrance.
    ///
    /// The installed caller first constructs its inert inline runtime header,
    /// then passes that same header here before storing this inert service in
    /// its reserved inline field. The header includes its service, SDK, finite
    /// operation and whole-result destinations. Dynamic representations remain
    /// separately payable before growth; this layout creates no receiving or
    /// effect permission.
    #[must_use]
    pub fn new_with_runtime_header_v4<T: Sized>(runtime_header: &T) -> Self {
        let layout = std::mem::size_of_val(runtime_header).checked_mul(2)
            .ok_or(AccountingError::ArithmeticOverflow {
                dimension: aos_sandbox_model::ResourceDimension::MemoryBytes,
            });
        // The Common supplier adds this amount once. Price both the actual
        // header's constructor and owning destination before native entry.
        let bytes = layout.as_ref().copied().unwrap_or(usize::MAX);
        let mut original = Self::with_runtime_layout(bytes);
        original.runtime_layout = Some(layout);
        original
    }

    fn with_runtime_layout(upper_inline_bytes: usize) -> Self {
        Self {
            common: FixedServiceReceivingCaptureV1::new_mount_v4(upper_inline_bytes),
            configuration: ProtectedMountBrokerConfigurationOriginalV4::new(),
            state_opening: MountStateCapturedJournalOpenV4::new(),
            session_opening: MountBrokerSessionCapturedJournalOpenV4::new(),
            store_opening: Default::default(), listener_opening: Default::default(),
            state: None, state_report: None,
            authority: None, credentials: None, store: None, runtime_layout: None,
            fixed: None, state_extent: None, store_extent: None,
            admitted: ResourceVector::ZERO, growth: None, callsite_geometry: None,
            startup: None, startup_body: None, startup_after: None,
            funding: std::array::from_fn(|_| None), entrance: None, native_before: None,
            configuration_result: None, store_result: None, listener_result: None,
            entered: false, ready: false, cold_borrowed: false, first: None, closed: Closed,
        }
    }

    /// Captures the real image-enrolled startup and its independent native after.
    ///
    /// # Errors
    /// Retains every reached native/model/Journal/configuration cause. No
    /// failed stage can reenter, replace its originals or reopen receiving.
    pub fn capture_startup_once_v4(&mut self) -> Result<()> {
        if self.entered {
            self.first.get_or_insert(Failure::Order);
            return Err(closed("Mount service startup cannot reenter"));
        }
        self.entered = true;
        if self.runtime_layout.as_ref().is_some_and(|result| result.is_err()) {
            self.first.get_or_insert(Failure::Geometry);
            return Err(closed("Mount actual runtime construction layout overflowed"));
        }
        self.entrance = Some(self.common.capture_once());
        if !matches!(self.entrance, Some(Ok(()))) {
            self.first.get_or_insert(Failure::Entrance);
            return Err(closed("Mount original image/native entrance is unavailable"));
        }
        self.startup = Some(self.capture_startup_inner());
        if matches!(self.startup, Some(Ok(()))) { Ok(()) }
        else { Err(closed("Mount startup failed with all original custody retained")) }
    }

    /// Borrows the first actual startup/native cause without further IO.
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            Failure::Entrance => self.common.failure(),
            Failure::Geometry => self.runtime_layout.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as &(dyn Error + 'static))
                .or_else(|| self.fixed.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
                .or_else(|| self.state_extent.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
                .or_else(|| self.store_extent.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
                .or_else(|| self.growth.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
                .or_else(|| self.callsite_geometry.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)),
            Failure::Funding | Failure::Before | Failure::After => self.common.service_startup_failure_v4(),
            Failure::Configuration => self.configuration.failure(),
            Failure::State => self.state_opening.failure(),
            Failure::Store => self.store_opening.failure(),
            Failure::Transfer => self.listener_opening.failure(),
            Failure::Order => None,
        }.or_else(|| self.startup.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or(Some(&self.closed))
    }
}

impl Drop for MountAttachmentAnchorServiceOriginalV4 {
    fn drop(&mut self) {
        if self.entered {
            // The installed service owns journals, credentials, listener and
            // failed prefixes through process lifetime, including cancellation.
            std::process::abort();
        }
    }
}

fn closed(reason: &'static str) -> MountError { MountError::Fence(reason) }

#[derive(Debug, thiserror::Error)]
enum MountServiceGeometryErrorV4 {
    #[error(transparent)]
    Arithmetic(#[from] AccountingError),
    #[error(transparent)]
    Mount(#[from] MountError),
    #[error(transparent)]
    Journal(#[from] JournalError),
}
