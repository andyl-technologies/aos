//! Retains fixed Source/TLS startup consumers under the same Controller pool.
//!
//! Only the genuine opening constructs these originals. The existing rich
//! native/semantic producers stay unchanged. A fixed profile scope surrounds
//! each read, retains independent posts after failure, and physically disposes
//! before this owner can advance the permanent pool's product phase.

use std::error::Error;
use std::sync::Arc;

use aos_sandbox_broker::controller_receiving::{
    ControllerReceivingOriginalV1, ControllerStartupCredentialReceivingV1,
};
use aos_sandbox_broker::controller_receiving::profile::ControllerProfileFailureViewV1;
use crate::hierarchy::controller_genesis_input::{
    ControllerSourceGenesisInputStartupV1, ProvisionedControllerSourceGenesisInputV1,
};
use crate::normal_root::ProductionControllerNormalRootProfileV1;
use crate::public_api_session::{PublicApiSessionAcceptor, PublicApiSessionError, PublicApiSessionStartupV1};

// Selects the actual Native producer only; phase/accounting stays in lower C.
#[derive(Clone, Copy)]
enum CredentialPurposeV1 { SourceGenesis, PublicTls }

#[derive(Debug, thiserror::Error)]
#[error("original startup credential receiving is closed")]
struct StartupCredentialClosedV1;

enum ProducerV1 {
    Source(ControllerSourceGenesisInputStartupV1),
    Public(PublicApiSessionStartupV1),
}

impl ProducerV1 {
    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Source(source) => source.failure(),
            Self::Public(public) => public.failure(),
        }
    }
}

enum CaptureV1 {
    Source(Result<(), ()>),
    Public(Result<(), PublicApiSessionError>),
}

impl CaptureV1 {
    fn is_positive(&self) -> bool {
        matches!(self, Self::Source(Ok(())) | Self::Public(Ok(())))
    }
}

enum OutputV1 {
    Source(Option<ProvisionedControllerSourceGenesisInputV1>),
    Public(PublicApiSessionAcceptor),
}

struct StartupCredentialReceivingV1 {
    profile: Arc<ProductionControllerNormalRootProfileV1>,
    purpose: CredentialPurposeV1,
    receiving: ControllerStartupCredentialReceivingV1,
    producer: Option<ProducerV1>,
    native: Option<CaptureV1>,
    transfer: Option<Result<(), StartupCredentialClosedV1>>,
    output: Option<OutputV1>,
    entered: bool,
    complete: bool,
    taken: bool,
}

impl StartupCredentialReceivingV1 {
    fn new(
        original: Arc<ControllerReceivingOriginalV1>,
        profile: Arc<ProductionControllerNormalRootProfileV1>,
        purpose: CredentialPurposeV1,
    ) -> Self {
        let receiving = match purpose {
            CredentialPurposeV1::SourceGenesis => ControllerStartupCredentialReceivingV1::source(original),
            CredentialPurposeV1::PublicTls => ControllerStartupCredentialReceivingV1::public_tls(original),
        };
        Self { profile, purpose, receiving, producer: None, native: None,
            transfer: None, output: None, entered: false, complete: false, taken: false }
    }

    fn prepare_once(&mut self) -> Result<(), ()> {
        self.receiving.prepare_once(self.profile.lower_original_v1()).map_err(|_| ())
    }

    fn is_prepared(&self) -> bool { self.receiving.is_prepared_v1() }

    fn capture_once(&mut self) -> Result<(), ()> {
        if self.entered || !self.receiving.is_prepared_v1() { return Err(()); }
        self.entered = true;
        let entry = self.receiving.begin_native_once(self.profile.lower_original_v1());
        if entry.is_ok() {
            // This actual rich producer grows only after the same complete
            // fixed operation and real before-profile/recipient conjunction.
            self.producer = Some(match self.purpose {
                CredentialPurposeV1::SourceGenesis => ProducerV1::Source(ControllerSourceGenesisInputStartupV1::new()),
                CredentialPurposeV1::PublicTls => ProducerV1::Public(PublicApiSessionStartupV1::new()),
            });
            self.capture_native();
        }
        // Actual body refusal cannot suppress the independently owed native
        // after/control/Ended post. No body Result or flag crosses this seam.
        let post = self.receiving.finish_native_once(self.profile.lower_original_v1());
        if entry.is_err() || post.is_err() || self.failure().is_some() || self.output.is_none() { return Err(()); }
        // The real normal output is already resident and take_success disposed
        // its proof temporaries. Only this private actual producer advances.
        self.receiving.complete_after_producer_disposal_once().map_err(|_| ())?;
        self.complete = true;
        Ok(())
    }

    fn capture_native(&mut self) {
        match self.producer.as_mut() {
            Some(ProducerV1::Source(source)) => {
                self.native = Some(CaptureV1::Source(source.capture_once()));
                if self.native.as_ref().is_some_and(CaptureV1::is_positive) {
                    self.output = source.take_success().map(OutputV1::Source);
                }
            }
            Some(ProducerV1::Public(public)) => {
                self.native = Some(CaptureV1::Public(public.capture_once()));
                if self.native.as_ref().is_some_and(CaptureV1::is_positive) {
                    self.output = public.take_success().map(OutputV1::Public);
                }
            }
            None => {}
        }
        self.transfer = Some(if self.output.is_some() {
            Ok(())
        } else {
            Err(StartupCredentialClosedV1)
        });
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.receiving.entry_failure_v1()
            .or_else(|| self.producer.as_ref().and_then(ProducerV1::failure))
            .or_else(|| match self.native.as_ref() {
                Some(CaptureV1::Public(Err(cause))) => Some(cause as &dyn Error),
                _ => None,
            })
            .or_else(|| self.transfer.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.receiving.post_failure_v1())
    }

    fn profile_failure_view_v1(&self) -> Option<ControllerProfileFailureViewV1<'_>> {
        let first = self.failure()?;
        let marker = self.receiving.profile_failure_marker_v1()?;
        if !std::ptr::eq(first as *const dyn Error as *const (), marker as *const dyn Error as *const ()) { return None; }
        self.profile.failure_view_v1()
    }

    fn take_output(&mut self) -> Option<OutputV1> {
        if !self.complete || self.taken || self.failure().is_some() {
            return None;
        }
        self.taken = true;
        self.output.take()
    }
}

impl Drop for StartupCredentialReceivingV1 {
    fn drop(&mut self) {
        if self.entered && !self.complete {
            // The actual partial producer and profile failure must remain
            // resident until process termination, including unwinding callers.
            std::process::abort();
        }
    }
}

/// Receives the fixed initial Source credentials under the original B pool.
///
/// Only the genuine Controller opening constructs this non-Clone owner.
#[doc(hidden)]
pub struct ControllerSourceGenesisReceivingV1 {
    original: StartupCredentialReceivingV1,
}

impl ControllerSourceGenesisReceivingV1 {
    pub(super) fn new(
        original: Arc<ControllerReceivingOriginalV1>,
        profile: Arc<ProductionControllerNormalRootProfileV1>,
    ) -> Self {
        Self {
            original: StartupCredentialReceivingV1::new(
                original, profile, CredentialPurposeV1::SourceGenesis,
            ),
        }
    }

    pub(super) fn prepare_once(&mut self) -> Result<(), ()> {
        self.original.prepare_once()
    }

    pub(super) fn is_prepared(&self) -> bool {
        self.original.is_prepared()
    }

    /// Captures the original native inputs and all independent profile posts.
    ///
    /// # Errors
    /// Returns a marker while [`Self::failure`] retains the earlier real cause.
    pub fn capture_once(&mut self) -> Result<(), ()> {
        self.original.capture_once()
    }

    /// Moves only the same completely checked normal optional input once.
    pub fn take_success(&mut self) -> Option<Option<ProvisionedControllerSourceGenesisInputV1>> {
        match self.original.take_output()? {
            OutputV1::Source(source) => Some(source),
            _ => std::process::abort(),
        }
    }

    /// Borrows the first native, semantic, arithmetic or profile refusal.
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.original.failure()
    }

    /// Borrows the rich guard only for this actual first Profile failure site.
    #[must_use]
    pub fn profile_failure_view_v1(&self) -> Option<ControllerProfileFailureViewV1<'_>> {
        self.original.profile_failure_view_v1()
    }
}

/// Receives the fixed initial public TLS state under the original B pool.
///
/// Only the genuine Controller opening constructs this non-Clone owner.
#[doc(hidden)]
pub struct ControllerPublicTlsReceivingV1 {
    original: StartupCredentialReceivingV1,
}

impl ControllerPublicTlsReceivingV1 {
    pub(super) fn new(
        original: Arc<ControllerReceivingOriginalV1>,
        profile: Arc<ProductionControllerNormalRootProfileV1>,
    ) -> Self {
        Self {
            original: StartupCredentialReceivingV1::new(
                original, profile, CredentialPurposeV1::PublicTls,
            ),
        }
    }

    pub(super) fn prepare_once(&mut self) -> Result<(), ()> {
        self.original.prepare_once()
    }

    pub(super) fn is_prepared(&self) -> bool {
        self.original.is_prepared()
    }

    /// Captures the original TLS prefixes and all independent profile posts.
    ///
    /// # Errors
    /// Returns a marker while [`Self::failure`] retains the earlier real cause.
    pub fn capture_once(&mut self) -> Result<(), ()> {
        self.original.capture_once()
    }

    /// Moves only the same completely checked normal acceptor once.
    pub fn take_success(&mut self) -> Option<PublicApiSessionAcceptor> {
        match self.original.take_output()? {
            OutputV1::Public(public) => Some(public),
            _ => std::process::abort(),
        }
    }

    /// Borrows the first native, semantic, arithmetic or profile refusal.
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.original.failure()
    }

    /// Borrows the rich guard only for this actual first Profile failure site.
    #[must_use]
    pub fn profile_failure_view_v1(&self) -> Option<ControllerProfileFailureViewV1<'_>> {
        self.original.profile_failure_view_v1()
    }
}
