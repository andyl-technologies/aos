//! Retains the native fixed startup journal through credential and final posts.
//!
//! Native Policy owns opening, replay, namespace claims and the five admission
//! bodies. This public facade retains the same owner and projects existing
//! Domain error categories. Unsupported platforms retain refusal-only APIs.

mod credential_writer;
pub use aos_sandbox_policy::signed_inputs::RootPolicyStartupDeploymentV1;
pub use credential_writer::RootStartupCredentialWriterV1;

use aos_sandbox_policy::signed_inputs::PolicyDeploymentHeadV1;
use ed25519_dalek::VerifyingKey;
use std::{error::Error, fmt};

use super::{
    CacheReadbackPinErrorV1, ClosedPolicyRootCasObservationV2, ControllerHoldPinErrorV1,
    PolicyCompilerJournalErrorV1, PolicyDeploymentHeadErrorV1, SourceHoldPinErrorV1,
};
use crate::journal::JournalError;
#[cfg(target_os = "linux")]
use aos_sandbox_policy::native::{
    RootStartupCredentialErrorV1 as CredentialError, RootStartupJournalErrorV1 as StartupError,
    RootStartupJournalOriginalV1 as NativeOwner,
};

/// Retains one actual startup journal through its independent final names duty.
///
/// Explicit ordinary and genuine selected construction remain separate. An
/// absent native owner is never initialized from a missing financial original.
pub struct RootPolicyStartupJournalV1 {
    #[cfg(target_os = "linux")]
    native: Option<NativeOwner>,
    local_failure: Option<JournalError>,
    finished: bool,
}

impl RootPolicyStartupJournalV1 {
    /// Creates vacant custody without opening storage or issuing authority.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            #[cfg(target_os = "linux")]
            native: None,
            local_failure: None,
            finished: false,
        }
    }

    /// Enters the explicit ordinary fixed opening once and retains its failure.
    pub fn open_once(&mut self) {
        #[cfg(target_os = "linux")]
        {
            if self.native.is_some() || self.finished {
                self.local_failure
                    .get_or_insert(JournalError::ProtectedBoundary);
                return;
            }
            self.native = Some(NativeOwner::new_ordinary_v1());
            if let Some(original) = self.native.as_mut() {
                // The whole failed opening stays resident. The returned marker
                // does not replace its actual native or replay diagnostic.
                if original.open_ordinary_once_v1().is_err() && original.failure_v1().is_none() {
                    self.local_failure
                        .get_or_insert(JournalError::ProtectedBoundary);
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        self.local_failure
            .get_or_insert(JournalError::UnsupportedProtectedOpen);
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn initialize_selected_once_v1(
        &mut self,
        provision: &aos_sandbox_broker::receiving::RootSelectedProvisionBorrowV1<'_>,
    ) -> Result<(), crate::normal_root::NormalRootStartupErrorV1> {
        if self.native.is_some() || self.finished {
            return Err(crate::normal_root::NormalRootStartupErrorV1::Service);
        }
        self.native = Some(NativeOwner::new_selected_v1(provision));
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn native_mut_v1(
        &mut self,
    ) -> Result<&mut NativeOwner, crate::normal_root::NormalRootStartupErrorV1> {
        self.native
            .as_mut()
            .ok_or(crate::normal_root::NormalRootStartupErrorV1::Service)
    }

    #[cfg(target_os = "linux")]
    fn ordinary_writer_v1(&mut self) -> Result<RootStartupCredentialWriterV1<'_>, CredentialError> {
        self.native
            .as_mut()
            .ok_or(StartupError::Closed)?
            .ordinary_credential_writer_v1()
            .map_err(CredentialError::from)
    }

    /// Reads unresolved custody from this same native writer before admission.
    ///
    /// # Errors
    /// Preserves failed opening, namespace, malformed history or ended borrowing.
    pub fn read_binding_hold(
        &mut self,
    ) -> Result<Option<ClosedPolicyRootCasObservationV2>, PolicyCompilerJournalErrorV1> {
        #[cfg(target_os = "linux")]
        {
            let original = self
                .native
                .as_mut()
                .ok_or(JournalError::ProtectedBoundary)?;
            original
                .read_binding_hold_data_v1()
                .map(|held| held.map(super::binding_v2::startup_binding_hold_observation_data_v1))
                .map_err(project_binding_read_error_v1)
        }
        #[cfg(not(target_os = "linux"))]
        Err(JournalError::UnsupportedProtectedOpen.into())
    }

    /// Admits the existing fixed credential through this explicit ordinary owner.
    ///
    /// # Errors
    /// Preserves the original credential category and actual native cause.
    pub fn admit_signer_pins(
        &mut self,
        deployment_generation: u64,
        deployment_key: &VerifyingKey,
        project_generation: u64,
        project_key: &VerifyingKey,
    ) -> Result<(), PolicyDeploymentHeadErrorV1> {
        #[cfg(target_os = "linux")]
        {
            self.ordinary_writer_v1()
                .map_err(PolicyDeploymentHeadErrorV1::from)?
                .admit_signer_pins(
                    deployment_generation,
                    deployment_key,
                    project_generation,
                    project_key,
                )
                .map_err(PolicyDeploymentHeadErrorV1::from)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (
                deployment_generation,
                deployment_key,
                project_generation,
                project_key,
            );
            Err(PolicyDeploymentHeadErrorV1::Journal(
                JournalError::UnsupportedProtectedOpen,
            ))
        }
    }

    /// Admits the existing fixed credential through this explicit ordinary owner.
    ///
    /// # Errors
    /// Preserves the original credential category and actual native cause.
    pub fn admit_deployment_head(
        &mut self,
        deployment: RootPolicyStartupDeploymentV1<'_>,
    ) -> Result<PolicyDeploymentHeadV1, PolicyDeploymentHeadErrorV1> {
        #[cfg(target_os = "linux")]
        {
            self.ordinary_writer_v1()
                .map_err(PolicyDeploymentHeadErrorV1::from)?
                .admit_deployment_head(deployment)
                .map_err(PolicyDeploymentHeadErrorV1::from)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (deployment);
            Err(PolicyDeploymentHeadErrorV1::Journal(
                JournalError::UnsupportedProtectedOpen,
            ))
        }
    }

    /// Admits the existing fixed credential through this explicit ordinary owner.
    ///
    /// # Errors
    /// Preserves the original credential category and actual native cause.
    pub fn admit_cache_pin(
        &mut self,
        credential: Option<&[u8]>,
    ) -> Result<(), CacheReadbackPinErrorV1> {
        #[cfg(target_os = "linux")]
        {
            self.ordinary_writer_v1()
                .map_err(CacheReadbackPinErrorV1::from)?
                .admit_cache_pin(credential)
                .map_err(CacheReadbackPinErrorV1::from)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (credential);
            Err(CacheReadbackPinErrorV1::Journal(
                JournalError::UnsupportedProtectedOpen,
            ))
        }
    }

    /// Admits the existing fixed credential through this explicit ordinary owner.
    ///
    /// # Errors
    /// Preserves the original credential category and actual native cause.
    pub fn admit_controller_pin(
        &mut self,
        credential: Option<&[u8]>,
    ) -> Result<(), ControllerHoldPinErrorV1> {
        #[cfg(target_os = "linux")]
        {
            self.ordinary_writer_v1()
                .map_err(ControllerHoldPinErrorV1::from)?
                .admit_controller_pin(credential)
                .map_err(ControllerHoldPinErrorV1::from)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (credential);
            Err(ControllerHoldPinErrorV1::Journal(
                JournalError::UnsupportedProtectedOpen,
            ))
        }
    }

    /// Admits the existing fixed credential through this explicit ordinary owner.
    ///
    /// # Errors
    /// Preserves the original credential category and actual native cause.
    pub fn admit_source_pin(
        &mut self,
        credential: Option<&[u8]>,
    ) -> Result<(), SourceHoldPinErrorV1> {
        #[cfg(target_os = "linux")]
        {
            self.ordinary_writer_v1()
                .map_err(SourceHoldPinErrorV1::from)?
                .admit_source_pin(credential)
                .map_err(SourceHoldPinErrorV1::from)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (credential);
            Err(SourceHoldPinErrorV1::Journal(
                JournalError::UnsupportedProtectedOpen,
            ))
        }
    }

    /// Attempts the same actual owner's independent final names post once.
    ///
    /// # Errors
    /// Preserves the original boundary marker while the native owner retains
    /// actual partial opening or final native/name/health refusal custody.
    pub fn finish_names_once(&mut self) -> Result<(), JournalError> {
        if self.finished {
            return Err(JournalError::ProtectedBoundary);
        }
        self.finished = true;
        #[cfg(target_os = "linux")]
        {
            self.native
                .as_mut()
                .ok_or(JournalError::ProtectedBoundary)?
                .finish_names_once_v1()
                .map_err(|_| JournalError::ProtectedBoundary)
        }
        #[cfg(not(target_os = "linux"))]
        Err(JournalError::UnsupportedProtectedOpen)
    }

    /// Borrows the same retained opening, native or final-post diagnostic.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        #[cfg(target_os = "linux")]
        if let Some(error) = self.native.as_ref().and_then(NativeOwner::failure_v1) {
            return Some(error);
        }
        self.local_failure.as_ref().map(|error| error as _)
    }

    /// Moves the entire same owner into an owning diagnostic until disposal.
    #[must_use]
    pub fn into_failure(self) -> impl Error {
        StartupJournalFailureV1 { owner: self }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn selected_adapter_control_bytes_v1() -> Option<usize> {
        use std::mem::size_of;
        size_of::<Self>()
            .checked_mul(3)?
            .checked_add(size_of::<Option<NativeOwner>>().checked_mul(2)?)?
            .checked_add(
                size_of::<Result<&mut NativeOwner, crate::normal_root::NormalRootStartupErrorV1>>()
                    .checked_mul(3)?,
            )?
            .checked_add(
                size_of::<(
                    &mut Self,
                    &aos_sandbox_broker::receiving::RootSelectedProvisionBorrowV1<'_>,
                )>()
                .checked_mul(3)?,
            )?
            .checked_add(size_of::<&mut Self>().checked_mul(6)?)?
            .checked_add(
                size_of::<Result<(), crate::normal_root::NormalRootStartupErrorV1>>()
                    .checked_mul(3)?,
            )?
            .checked_add(
                size_of::<aos_sandbox_policy::native::RootStartupBindingReadErrorV1>()
                    .checked_mul(3)?,
            )?
            .checked_add(size_of::<PolicyCompilerJournalErrorV1>().checked_mul(3)?)?
            .checked_add(
                size_of::<aos_sandbox_policy::publication::PolicyCompilerJournalErrorV1>()
                    .checked_mul(3)?,
            )?
            .checked_add(
                size_of::<aos_sandbox_policy::native::PolicyNativeJournalErrorV1>()
                    .checked_mul(3)?,
            )?
            .checked_add(size_of::<JournalError>().checked_mul(6)?)?
            .checked_add(
                size_of::<
                    Result<
                        Option<aos_sandbox_protocol::policy_data::binding_v2::RootBindingHoldV1>,
                        aos_sandbox_policy::native::RootStartupBindingReadErrorV1,
                    >,
                >()
                .checked_mul(3)?,
            )?
            .checked_add(
                size_of::<
                    Result<Option<ClosedPolicyRootCasObservationV2>, PolicyCompilerJournalErrorV1>,
                >()
                .checked_mul(3)?,
            )?
            .checked_add(
                size_of::<aos_sandbox_protocol::policy_data::binding_v2::RootBindingHoldV1>()
                    .checked_mul(3)?,
            )?
            .checked_add(size_of::<ClosedPolicyRootCasObservationV2>().checked_mul(3)?)?
            .checked_add(size_of::<Option<ClosedPolicyRootCasObservationV2>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<(), JournalError>>().checked_mul(3)?)?
            .checked_add(size_of::<bool>().checked_mul(3)?)
    }
}

#[cfg(target_os = "linux")]
fn project_binding_read_error_v1(
    error: aos_sandbox_policy::native::RootStartupBindingReadErrorV1,
) -> PolicyCompilerJournalErrorV1 {
    use aos_sandbox_policy::native::{
        PolicyNativeJournalErrorV1 as Native, RootStartupBindingReadErrorV1 as Read,
    };
    match error {
        Read::Startup(StartupError::Names | StartupError::Closed) => JournalError::ProtectedBoundary.into(),
        Read::Native(Native::Mechanical(error)) | Read::Startup(StartupError::Native(Native::Mechanical(error))) => JournalError::from(error).into(),
        Read::Native(Native::Root(error)) | Read::Startup(StartupError::Native(Native::Root(error))) => JournalError::RootNative(error).into(),
        Read::Native(Native::RootAppend(error)) | Read::Startup(StartupError::Native(Native::RootAppend(error))) => JournalError::RootAppendOriginal(error).into(),
        Read::Native(Native::Financial(error)) | Read::Startup(StartupError::Native(Native::Financial(error))) => JournalError::RootFinancial(error).into(),
        Read::Native(error @ (Native::Q04Current(_) | Native::TargetCurrent(_) | Native::NativePost(_)))
        | Read::Startup(StartupError::Native(error @ (Native::Q04Current(_) | Native::TargetCurrent(_) | Native::NativePost(_)))) =>
            aos_sandbox_policy::publication::PolicyCompilerJournalErrorV1::from(error).into(),
        Read::Data(aos_sandbox_protocol::policy_data::binding_v2::BindingDataErrorV1::UnauthenticatedCandidate) => PolicyCompilerJournalErrorV1::UnauthenticatedCandidate,
    }
}

struct StartupJournalFailureV1 {
    owner: RootPolicyStartupJournalV1,
}

impl fmt::Debug for StartupJournalFailureV1 {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output
            .debug_struct("StartupJournalFailureV1")
            .field("cause", &self.owner.failure())
            .finish()
    }
}

impl fmt::Display for StartupJournalFailureV1 {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.owner.failure() {
            Some(cause) => fmt::Display::fmt(cause, output),
            None => output.write_str("Root startup journal has no completed failure observation"),
        }
    }
}

impl Error for StartupJournalFailureV1 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.owner.failure()
    }
}
