//! Selects the actual initial Root capture and retains the V6 refusal.
//!
//! The scalar activation count selects storage only. The original four-role
//! owner captures the complete table before parsing role names, then retains
//! its original image-policy and PID1-delivery observations. The existing
//! zero/two-role capture remains the sole ordinary continuation.
//!
//! V6 cannot proceed to profile decoding, PID1 transport, credentials or a
//! protected journal: their complete pre-open receiving supplier is absent.
//! Retained representation DATA is not payment or physical fit. A failed V6
//! owner stays resident until intentional process termination, without refund,
//! retry, drain, receiving authority or activation.

use std::env::VarError;
use std::error::Error;
use std::num::ParseIntError;

use crate::controller_resource_reservation::RootReceivingOriginalV1;
use crate::journal::{
    JournalError, ProtectedJournalPreopenReplayExtentV1,
    ProtectedJournalPreopenUnpricedPrerequisitesV1::
        AllocatorDecoderErrorsNativePathsAndExternalChallenges,
};
use crate::policy_compiler::RootPolicyStartupJournalV1;

use super::{NormalRootStartupErrorV1, ProductionNormalRootStartupCaptureV1};

/// Retains one actual initial Root capture and its reached native results.
///
/// Construction performs no observation. The daemon must install this owner
/// before observing activation metadata or opening any other descriptor.
/// Only a completed ordinary capture moves out; four-role custody cannot
/// escape the unresolved V6 receiving boundary.
#[must_use = "retain failed startup custody until intentional process termination"]
pub struct ProductionNormalRootInitialStartupV1 {
    count_text: Option<Result<String, VarError>>,
    count: Option<Result<usize, ParseIntError>>,
    ordinary: Option<Result<ProductionNormalRootStartupCaptureV1, NormalRootStartupErrorV1>>,
    root: Option<RootReceivingOriginalV1>,
    preopen: Option<Result<ProtectedJournalPreopenReplayExtentV1, JournalError>>,
    refusal: Option<InitialStartupRefusalV1>,
    attempted: bool,
    armed: bool,
}

#[derive(Debug, thiserror::Error)]
enum InitialStartupRefusalV1 {
    #[error("Root initial startup capture is closed")]
    Closed,
    #[error("Root original four-role capture failed")]
    Capture,
    #[error("Root original image-policy and PID1 delivery differ")]
    Original,
    #[error("Root configured pre-open replay extent is unavailable")]
    Preopen,
    #[error("Root pre-open receiving lacks allocator, decoder/error, native/path and external-history suppliers")]
    UnpricedReceiving,
}

impl ProductionNormalRootInitialStartupV1 {
    /// Creates vacant resident slots without parsing names or duplicating FDs.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            count_text: None,
            count: None,
            ordinary: None,
            root: None,
            preopen: None,
            refusal: None,
            attempted: false,
            armed: true,
        }
    }

    /// Captures once and borrows the permanently retained V6 failure.
    ///
    /// V6 authenticates only the original pair's canonical DATA. Complete
    /// receiving and genuine producer/recipient admission remain unavailable;
    /// no property observer, decoder, credential read or journal open follows.
    ///
    /// # Errors
    ///
    /// Preserves actual capture and original-pair causes. A complete four-role
    /// capture refuses its missing pre-open suppliers. Reentry never retries an
    /// observation. The caller must terminate without dropping failed custody.
    pub fn capture_once(&mut self) -> Result<(), &(dyn Error + 'static)> {
        if self.attempted {
            self.refusal.get_or_insert(InitialStartupRefusalV1::Closed);
            return Err(self.failure());
        }
        self.attempted = true;

        let result = self.capture_body();
        match result {
            Ok(()) => Ok(()),
            Err(refusal) => {
                self.refusal = Some(refusal);
                Err(self.failure())
            }
        }
    }

    /// Moves only the same ordinary capture result without another effect.
    ///
    /// The checked handoff disarms this emptied selection owner. The original
    /// ordinary success/error and disposal contract remains unchanged. No
    /// four-role attempt can disarm or continue through legacy.
    ///
    /// # Errors
    ///
    /// The moved ordinary result preserves the existing normal capture's
    /// activation and kernel refusals without replacing or retrying them.
    #[must_use]
    pub fn take_ordinary_capture(
        &mut self,
    ) -> Option<Result<ProductionNormalRootStartupCaptureV1, NormalRootStartupErrorV1>> {
        if !self.attempted
            || self.refusal.is_some()
            || self.root.is_some()
            || self.preopen.is_some()
            || self.ordinary.is_none()
        {
            return None;
        }

        let capture = self.ordinary.take();
        self.armed = false;
        capture
    }

    fn capture_body(&mut self) -> Result<(), InitialStartupRefusalV1> {
        // Count and its allocation/native parse results remain in this owner.
        // Full names parsing belongs to the chosen original capture, after
        // the fixed four-role table has parked every returned descriptor.
        self.count_text = Some(std::env::var("LISTEN_FDS"));
        self.count = self.count_text
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .map(|text| text.parse::<usize>());
        if !matches!(self.count, Some(Ok(4))) {
            self.ordinary = Some(ProductionNormalRootStartupCaptureV1::capture());
            return Ok(());
        }

        self.root = Some(RootReceivingOriginalV1::new());
        let root = self.root.as_mut().ok_or(InitialStartupRefusalV1::Capture)?;
        root.capture_once()
            .map_err(|_| InitialStartupRefusalV1::Capture)?;
        root.authenticate_once()
            .map_err(|_| InitialStartupRefusalV1::Original)?;

        // This uses the same configured limits as the native Root opener.
        // Its explicit unpriced obligations stop this invocation before any
        // variable receiving is entered; no observed later size retrofunds it.
        self.preopen = Some(RootPolicyStartupJournalV1::preopen_replay_extent());
        let extent = self.preopen
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(InitialStartupRefusalV1::Preopen)?;
        match extent.unpriced {
            AllocatorDecoderErrorsNativePathsAndExternalChallenges => {
                Err(InitialStartupRefusalV1::UnpricedReceiving)
            }
        }
    }

    fn failure(&self) -> &(dyn Error + 'static) {
        if let Some(cause) = self.root.as_ref().and_then(RootReceivingOriginalV1::failure) {
            return cause;
        }
        if let Some(Err(cause)) = &self.preopen {
            return cause;
        }
        if let Some(Err(cause)) = &self.ordinary {
            return cause;
        }
        self.refusal
            .as_ref()
            .map(|cause| cause as &(dyn Error + 'static))
            .unwrap_or(&InitialStartupRefusalV1::Closed)
    }
}

impl Default for ProductionNormalRootInitialStartupV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ProductionNormalRootInitialStartupV1 {
    fn drop(&mut self) {
        if self.armed {
            std::process::abort();
        }
    }
}
