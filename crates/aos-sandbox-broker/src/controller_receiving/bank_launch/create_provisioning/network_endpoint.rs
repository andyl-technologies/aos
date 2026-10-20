//! Reuses fixed endpoint custody under the genuine active Start native turn.
//!
//! The enclosing Domain Start/Root owner supplies semantic admission and the
//! complete current representation. These ports only join that same C/native
//! turn and reuse the existing selected endpoint engines. Initial-B claims and
//! their financial controls are never constructed or borrowed here.

use super::*;
use std::sync::atomic::AtomicBool;
use aos_sandbox_core::AccountingError;
use crate::controller_receiving::ControllerInitialBrokerSessionRoleV1 as Role;
use crate::endpoint_native_files::{ControllerEndpointExecutionOriginalV1,
    ControllerEndpointExecutionCaptureErrorV1, ControllerEndpointNativeCustodyCaptureV1,
    ControllerEndpointNativeCustodyV1, EndpointNativeFileOpenOriginalV1,
    EndpointNativeFileV1, EndpointNativeSelectedOriginV1};

/// Retains the fixed Network endpoint native association for one Start turn.
///
/// Empty construction performs no IO. Preparation requires the actual active
/// native original, physical writer, confirmed launch and admitted profile,
/// and pays the complete endpoint recipe before allocation or native entry.
/// SDK-owned endpoint/floor observations and independently owed C/Root posts
/// remain separately mandatory; this owner cannot assert their completion.
#[must_use]
pub struct ControllerStartResourceEndpointOriginalV2 {
    role: Role,
    entered: bool,
    original: Option<Arc<ControllerReceivingOriginalV1>>,
    turn: Option<Arc<AtomicBool>>,
    identity: Option<Arc<ControllerWriterIdentityV1>>,
    geometry: Option<Result<ResourceVector, AccountingError>>,
    preparation: Option<Result<(), ControllerBankLaunchErrorV1>>,
    current: Option<Result<(), ControllerBankLaunchErrorV1>>,
    disposition: Option<Result<(), ControllerBankLaunchErrorV1>>,
    execution: Option<Result<ControllerEndpointExecutionOriginalV1,
        ControllerEndpointExecutionCaptureErrorV1>>,
    directory: Option<Result<(), ControllerReceivingErrorV1>>,
    origin: Option<Arc<EndpointNativeSelectedOriginV1>>,
    custody: Option<Result<(), ControllerReceivingErrorV1>>,
    completed: Option<Arc<ControllerEndpointNativeCustodyV1>>,
    first: Option<Failure>,
    closed: ControllerBankLaunchErrorV1,
}

#[derive(Clone, Copy)]
enum Failure { Geometry, Preparation, Current, Execution, Directory, Custody, Order }

impl Default for ControllerStartResourceEndpointOriginalV2 {
    fn default() -> Self {
        Self::new()
    }
}

impl ControllerStartResourceEndpointOriginalV2 {
    /// Creates only inert destinations without a role claim or native handle.
    #[must_use]
    pub fn new() -> Self { Self::for_role_v2(Role::Network) }

    /// Creates the inert fixed Mount destination, without native authority.
    #[must_use]
    pub fn mount_v2() -> Self { Self::for_role_v2(Role::Mount) }

    /// Creates only inert Host endpoint destinations for the private catalog interval.
    ///
    /// The actual Start/Root catalog lender still admits the complete shape and
    /// captures this endpoint through the same native engine before use.
    #[doc(hidden)]
    #[must_use]
    pub fn host_catalog_v2() -> Self { Self::for_role_v2(Role::Host) }

    fn for_role_v2(role: Role) -> Self {
        Self { role,
            entered: false, original: None, turn: None, identity: None,
            geometry: None, preparation: None, current: None, disposition: None, execution: None,
            directory: None, origin: None, custody: None, completed: None,
            first: None, closed: ControllerBankLaunchErrorV1::Conflict,
        }
    }

    /// Prices the actual capsule, selected backing and native self-capture peak.
    ///
    /// The caller additionally supplies the actual SDK's complete endpoint,
    /// floor, Journal and HELLO shape. This bound grants none of those objects.
    ///
    /// # Errors
    /// Refuses checked compiled-layout or descriptor-count overflow.
    pub fn receiving_demand_v2() -> Result<ResourceVector, AccountingError> {
        use aos_sandbox_linux::self_execution::RetainedSelfExecutionGuard as Guard;
        let overflow = AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes };
        let bytes = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(EndpointNativeFileV1::selected_origin_heap_bytes_v1()))
            .and_then(|bytes| bytes.checked_add(4usize.checked_mul(
                EndpointNativeFileV1::selected_descriptor_heap_bytes_v1())?))
            .and_then(|bytes| bytes.checked_add(ControllerEndpointNativeCustodyCaptureV1::receiving_heap_bytes_v1()))
            .and_then(|bytes| bytes.checked_add(Guard::selected_capture_heap_bytes_v1()))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(overflow)?;
        let files = Guard::selected_capture_opened_file_bound_v1().checked_add(4)
            .and_then(|files| u64::try_from(files).ok())
            .ok_or(AccountingError::ArithmeticOverflow { dimension: D::OpenFiles })?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes).with(D::OpenFiles, files))
    }

    /// Binds this capsule only after the same native complete demand is admitted.
    ///
    /// # Errors
    /// Retains wrong purpose, same-owner failure or original capacity refusal.
    pub fn prepare_once_v2<P>(&mut self,
        native: &mut ControllerCreateProvisioningReceivingV1,
        writer: &ControllerCoordinatorWriterV1<P>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1, complete: ResourceVector,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if self.entered {
            self.first.get_or_insert(Failure::Order);
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.entered = true;
        self.geometry = Some(Self::receiving_demand_v2().and_then(|own| complete.checked_add(own)));
        self.preparation = Some((|| {
            if native.purpose != ContinuationReceivingPurposeV1::CreateProvisioning {
                return Err(ControllerBankLaunchErrorV1::Conflict);
            }
            let complete = self.geometry.as_ref().and_then(|value| value.as_ref().ok()).copied()
                .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
            native.require_complete_representation_v1(writer, launch, profile, complete)?;
            self.original = Some(Arc::clone(&native.original));
            self.identity = Some(Arc::clone(&native.identity));
            self.turn = Some(Arc::clone(native.turn_identity.as_ref()
                .ok_or(ControllerBankLaunchErrorV1::Conflict)?));
            Ok(())
        })());
        if self.geometry.as_ref().is_some_and(Result::is_err) {
            self.first = Some(Failure::Geometry);
        } else if !matches!(self.preparation, Some(Ok(()))) {
            self.first = Some(Failure::Preparation);
        }
        if self.first.is_some() { Err(ControllerBankLaunchErrorV1::Conflict) } else { Ok(()) }
    }

    /// Rejoins the same active turn without an observation or new account.
    ///
    /// # Errors
    /// Refuses changed native turn, writer, profile, launch or a prior refusal.
    pub fn require_current_v2<P>(&mut self, native: &ControllerCreateProvisioningReceivingV1,
        writer: &ControllerCoordinatorWriterV1<P>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if self.first.is_some() { return Err(ControllerBankLaunchErrorV1::Conflict); }
        self.current = Some((|| {
            if !matches!(self.preparation, Some(Ok(())))
                || !self.original.as_ref().is_some_and(|held| Arc::ptr_eq(held, &native.original))
                || !self.identity.as_ref().is_some_and(|held| Arc::ptr_eq(held, &native.identity))
                || !self.turn.as_ref().zip(native.turn_identity.as_ref())
                    .is_some_and(|(held, actual)| Arc::ptr_eq(held, actual))
            {
                return Err(ControllerBankLaunchErrorV1::Conflict);
            }
            native.require_current_v1(writer, launch, profile)
        })());
        if matches!(self.current, Some(Ok(()))) { Ok(()) }
        else {
            self.first.get_or_insert(Failure::Current);
            Err(ControllerBankLaunchErrorV1::Conflict)
        }
    }

    /// Captures the same C's fixed self guard through the sole native engine.
    ///
    /// # Errors
    /// Keeps the first actual capture error and refuses replacement/reentry.
    pub fn capture_execution_once_v2<P>(&mut self, native: &ControllerCreateProvisioningReceivingV1,
        writer: &ControllerCoordinatorWriterV1<P>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<ControllerEndpointExecutionOriginalV1, ControllerEndpointExecutionCaptureErrorV1> {
        if self.execution.is_some() || self.require_current_v2(native, writer, launch, profile).is_err() {
            self.first.get_or_insert(Failure::Order);
            return Err(ControllerEndpointExecutionCaptureErrorV1::Unavailable);
        }
        self.execution = Some(native.original.capture_fixed_session_execution_v1(self.role));
        match self.execution.as_ref() {
            Some(Ok(execution)) => Ok(execution.share_v1()),
            Some(Err(cause)) => {
                self.first.get_or_insert(Failure::Execution);
                Err(cause.clone())
            }
            None => Err(ControllerEndpointExecutionCaptureErrorV1::Unavailable),
        }
    }

    /// Opens only the fixed Network custody directory under its paid origin.
    ///
    /// # Errors
    /// Retains currentness/reentry refusal; the destination retains native IO.
    pub fn capture_directory_once_v2<P>(&mut self, native: &ControllerCreateProvisioningReceivingV1,
        writer: &ControllerCoordinatorWriterV1<P>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1, destination: &mut EndpointNativeFileOpenOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.require_current_v2(native, writer, launch, profile)?;
        if self.directory.is_some() || destination.entered() || !matches!(self.execution, Some(Ok(_))) {
            self.first.get_or_insert(Failure::Order);
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.origin = Some(EndpointNativeSelectedOriginV1::new(&native.original, self.role));
        self.directory = Some(Ok(()));
        if let Some(origin) = &self.origin { destination.selected_directory_once(origin); }
        Ok(())
    }

    /// Parks the actual successful native aggregate without adopting raw files.
    ///
    /// # Errors
    /// Keeps every partial input in the existing custody destination on error.
    pub fn capture_custody_once_v2<P>(&mut self, native: &ControllerCreateProvisioningReceivingV1,
        writer: &ControllerCoordinatorWriterV1<P>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        destination: &mut ControllerEndpointNativeCustodyCaptureV1,
        execution: &mut Option<ControllerEndpointExecutionOriginalV1>,
        post: &mut Option<aos_sandbox_linux::self_execution::SelfExecutionObservationV1>,
        files: [&EndpointNativeFileV1; 4],
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.require_current_v2(native, writer, launch, profile)?;
        if self.custody.is_some() || !matches!(self.directory, Some(Ok(()))) {
            self.first.get_or_insert(Failure::Order);
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.custody = Some((|| {
            let origin = self.origin.as_ref().ok_or(ControllerReceivingErrorV1::Conflict)?;
            destination.capture_once(execution, post, files, origin, &native.original, self.role)?;
            let completed = destination.completed().ok_or(ControllerReceivingErrorV1::Conflict)?;
            if completed.retained_open_file_count_v1() != Some(6) {
                return Err(ControllerReceivingErrorV1::Conflict);
            }
            self.completed = Some(Arc::clone(completed));
            Ok(())
        })());
        if matches!(self.custody, Some(Ok(()))) { Ok(()) }
        else {
            self.first.get_or_insert(Failure::Custody);
            Err(ControllerBankLaunchErrorV1::Conflict)
        }
    }

    /// Prepares physical endpoint disposal under the same completed C original.
    ///
    /// The opening turn has ended. This joins the persistent writer and C
    /// original, then the genuinely completed current turn; it never compares
    /// the retired opening-turn identity with a later turn's identity.
    ///
    /// # Errors
    /// Retains reentry, a prior failed native prefix, foreign C/writer/profile
    /// or incomplete independently owed current native posts.
    pub fn prepare_positive_disposition_v2<P>(&mut self,
        native: &ControllerCreateProvisioningReceivingV1,
        writer: &ControllerCoordinatorWriterV1<P>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if self.disposition.is_some() || self.first.is_some() {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.disposition = Some((|| {
            if !self.entered || !matches!(self.custody, Some(Ok(())))
                || !self.original.as_ref().is_some_and(|held| Arc::ptr_eq(held, &native.original))
                || !self.identity.as_ref().is_some_and(|held| Arc::ptr_eq(held, &native.identity)) {
                return Err(ControllerBankLaunchErrorV1::Conflict);
            }
            native.require_completed_original_v1(writer, launch, profile)
        })());
        if matches!(self.disposition, Some(Ok(()))) { Ok(()) }
        else { Err(ControllerBankLaunchErrorV1::Conflict) }
    }

    /// Disposes the positive native aggregate after its actual upper owners.
    ///
    /// # Errors
    /// Refuses a missing genuine completed-C preparation or another owner still
    /// retaining the native custody. Failure leaves this capsule resident.
    pub fn complete_positive_disposition_v2(&mut self) -> Result<(), ControllerBankLaunchErrorV1> {
        if !matches!(self.disposition, Some(Ok(()))) || self.first.is_some()
            || self.completed.as_ref().is_none_or(|held| Arc::strong_count(held) != 1) {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        drop(self.completed.take());
        drop(self.execution.take());
        drop(self.origin.take());
        self.entered = false;
        Ok(())
    }

    /// Borrows only the same fully owning native aggregate, as custody DATA.
    ///
    /// This does not establish SDK HELLO/floor completion or Session authority.
    #[must_use]
    pub fn completed_custody_v2(&self) -> Option<&Arc<ControllerEndpointNativeCustodyV1>> {
        if self.first.is_some() || !matches!(self.custody, Some(Ok(()))) { return None; }
        self.completed.as_ref()
    }

    /// Borrows the chronological actual refusal without another native attempt.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        if let Some(Err(cause)) = self.disposition.as_ref() { return Some(cause); }
        match self.first? {
            Failure::Geometry => self.geometry.as_ref()?.as_ref().err().map(|cause| cause as _),
            Failure::Preparation => self.preparation.as_ref()?.as_ref().err().map(|cause| cause as _),
            Failure::Current => self.current.as_ref()?.as_ref().err().map(|cause| cause as _),
            Failure::Execution => self.execution.as_ref()?.as_ref().err().map(|cause| cause as _),
            Failure::Directory => self.directory.as_ref()?.as_ref().err().map(|cause| cause as _),
            Failure::Custody => self.custody.as_ref()?.as_ref().err().map(|cause| cause as _),
            Failure::Order => None,
        }.or(Some(&self.closed))
    }
}

impl Drop for ControllerStartResourceEndpointOriginalV2 {
    fn drop(&mut self) {
        if self.entered { std::process::abort(); }
    }
}
