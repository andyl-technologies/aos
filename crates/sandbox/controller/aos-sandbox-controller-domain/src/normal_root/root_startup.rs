//! Selects and retains the actual original Root receiving continuation.
//!
//! The scalar activation count selects storage only. Four-role custody parks
//! the actual table before names, authenticates its original image/delivery and
//! receives the bounded profile/PID1 joins under its genuine installed RootR.
//! The same original then moves through full selected startup and the separate
//! actual held-prefix journal permit before credentials or serving.
//! Failed originals stay resident until intentional process termination;
//! receiving never refunds, reconstructs or rearms an invocation.

use std::env::VarError;
use std::error::Error;
use std::num::ParseIntError;

use crate::controller_resource_reservation::RootReceivingOriginalV1;

use super::{NormalRootStartupErrorV1, ProductionNormalRootStartupCaptureV1};

/// Retains one actual initial Root capture and its reached native results.
///
/// Construction performs no observation. The daemon must install this owner
/// before observing activation metadata or opening any other descriptor.
/// A positive checked handoff moves the actual chosen originals together;
/// it grants no Source, journal, signer or serving authority.
#[must_use = "retain failed startup custody until intentional process termination"]
pub struct ProductionNormalRootInitialStartupV1 {
    count_text: Option<Result<String, VarError>>,
    count: Option<Result<usize, ParseIntError>>,
    ordinary: Option<Result<ProductionNormalRootStartupCaptureV1, NormalRootStartupErrorV1>>,
    root: Option<RootReceivingOriginalV1>,
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
    #[error("Root original bounded profile receiving failed")]
    ProfileReceiving,
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
            refusal: None,
            attempted: false,
            armed: true,
        }
    }

    /// Captures once and retains original receiving results before continuation.
    ///
    /// The genuine RootR negative prefix authenticates actual PID1/profile and
    /// recipient joins. Full selected startup and actual captured journal
    /// admission remain separate connected stages before credential loading.
    ///
    /// # Errors
    /// Preserves actual capture, original-pair, decoder and native first causes.
    /// Reentry never repeats an observation. Failed custody must remain held
    /// through intentional process termination.
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
            || self.ordinary.is_none()
        {
            return None;
        }

        let capture = self.ordinary.take();
        self.armed = false;
        capture
    }

    /// Moves the same positively received initial selection into startup custody.
    ///
    /// This performs no observation. Four-role originals move together and
    /// cannot continue through the legacy descriptor path. The selected image
    /// checks and actual journal permit still precede credential admission.
    #[must_use]
    pub fn take_capture(
        &mut self,
    ) -> Option<Result<ProductionNormalRootStartupCaptureV1, NormalRootStartupErrorV1>> {
        if !self.attempted || self.refusal.is_some() {
            return None;
        }
        if self.ordinary.is_some() {
            return self.take_ordinary_capture();
        }
        let original = self.root.as_ref()?;
        if original.failure().is_some() {
            return None;
        }
        let original = self.root.take()?;
        self.armed = false;
        Some(Ok(ProductionNormalRootStartupCaptureV1 { descriptors: None, root: Some(original) }))
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
        root.receive_profile_once()
            .map_err(|_| InitialStartupRefusalV1::ProfileReceiving)?;

        Ok(())
    }

    fn failure(&self) -> &(dyn Error + 'static) {
        if let Some(cause) = self.root.as_ref().and_then(RootReceivingOriginalV1::failure) {
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
