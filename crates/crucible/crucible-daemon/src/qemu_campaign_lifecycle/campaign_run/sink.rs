//! Streaming delivery of guarded campaign progress to the caller.
//!
//! A guarded campaign can accept one observation per scenario choice, so its
//! accepted observations, branch acceptances, and watch frames grow with the
//! run. The owner therefore does not retain them. It hands each one to a
//! caller-supplied [`GuardedCampaignRunSink`] synchronously, while the
//! attempt's evidence snapshot still holds its log segments, and then drops
//! it. The returned [`super::GuardedDefaultCampaignRun`] keeps only counts and
//! the terminal observation (RFC-0020 CMEAS-29).
//!
//! ```text
//! incorporated attempt -> materialize observation -> sink.on_observation
//!                      -> optional watch frame    -> sink.on_watch_frame
//! accepted exploration request                    -> sink.on_branch_acceptance
//! ```

use std::error::Error;
use std::fmt;

use super::{
    GuardedCampaignBranchAcceptance, GuardedDefaultCampaignObservation,
    GuardedDefaultCampaignWatchFrame,
};

/// Receives guarded campaign progress while the campaign runs.
///
/// Every method runs on the campaign's own thread before the owner advances,
/// so a slow sink lengthens the run. Sinks should fold or summarize what they
/// need and return. The borrowed values are dropped once the call returns;
/// a sink that keeps every observation reintroduces the run-length memory the
/// owner avoids. An error from any method stops the campaign and is returned
/// as [`super::GuardedDefaultCampaignRunError::Sink`].
///
/// Every method has a no-op default, so a sink implements only the events it
/// consumes.
pub trait GuardedCampaignRunSink {
    /// Receives one accepted observation in acceptance order.
    ///
    /// The observation's evidence snapshot can stream the attempt's event log
    /// one segment at a time during this call.
    ///
    /// # Errors
    ///
    /// Returns [`GuardedCampaignRunSinkError`] to stop the campaign.
    fn on_observation(
        &mut self,
        observation: &GuardedDefaultCampaignObservation,
    ) -> Result<(), GuardedCampaignRunSinkError> {
        let _ = observation;
        Ok(())
    }

    /// Receives one repository-accepted exploration branch request.
    ///
    /// # Errors
    ///
    /// Returns [`GuardedCampaignRunSinkError`] to stop the campaign.
    fn on_branch_acceptance(
        &mut self,
        acceptance: GuardedCampaignBranchAcceptance,
    ) -> Result<(), GuardedCampaignRunSinkError> {
        let _ = acceptance;
        Ok(())
    }

    /// Receives one authenticated watch frame, when the request asked for them.
    ///
    /// # Errors
    ///
    /// Returns [`GuardedCampaignRunSinkError`] to stop the campaign.
    fn on_watch_frame(
        &mut self,
        frame: &GuardedDefaultCampaignWatchFrame,
    ) -> Result<(), GuardedCampaignRunSinkError> {
        let _ = frame;
        Ok(())
    }
}

/// Sink that discards every event, for callers that need only the result.
#[derive(Clone, Copy, Debug, Default)]
pub struct DiscardGuardedCampaignProgress;

impl GuardedCampaignRunSink for DiscardGuardedCampaignProgress {}

/// Failure reported by a [`GuardedCampaignRunSink`].
#[derive(Debug)]
pub struct GuardedCampaignRunSinkError {
    source: Box<dyn Error + Send + Sync>,
}

impl GuardedCampaignRunSinkError {
    /// Wraps the sink's own failure.
    #[must_use]
    pub fn new(source: impl Into<Box<dyn Error + Send + Sync>>) -> Self {
        Self {
            source: source.into(),
        }
    }
}

impl fmt::Display for GuardedCampaignRunSinkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.source.fmt(formatter)
    }
}

impl Error for GuardedCampaignRunSinkError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}

/// Test sink that keeps every delivered event for assertions.
///
/// It retains the run-length state the owner streams, so it exists only for
/// tests with a handful of attempts.
#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Debug, Default)]
pub struct GuardedCampaignRunRecorder {
    observations: Vec<GuardedDefaultCampaignObservation>,
    branch_acceptances: Vec<GuardedCampaignBranchAcceptance>,
    watch_frames: Vec<GuardedDefaultCampaignWatchFrame>,
}

#[cfg(any(test, feature = "test-support"))]
impl GuardedCampaignRunRecorder {
    /// Returns every delivered observation in acceptance order.
    #[must_use]
    pub fn observations(&self) -> &[GuardedDefaultCampaignObservation] {
        &self.observations
    }

    /// Returns every delivered branch acceptance in acceptance order.
    #[must_use]
    pub fn branch_acceptances(&self) -> &[GuardedCampaignBranchAcceptance] {
        &self.branch_acceptances
    }

    /// Returns every delivered watch frame in delivery order.
    #[must_use]
    pub fn watch_frames(&self) -> &[GuardedDefaultCampaignWatchFrame] {
        &self.watch_frames
    }
}

#[cfg(any(test, feature = "test-support"))]
impl GuardedCampaignRunSink for GuardedCampaignRunRecorder {
    fn on_observation(
        &mut self,
        observation: &GuardedDefaultCampaignObservation,
    ) -> Result<(), GuardedCampaignRunSinkError> {
        self.observations.push(observation.clone());
        Ok(())
    }

    fn on_branch_acceptance(
        &mut self,
        acceptance: GuardedCampaignBranchAcceptance,
    ) -> Result<(), GuardedCampaignRunSinkError> {
        self.branch_acceptances.push(acceptance);
        Ok(())
    }

    fn on_watch_frame(
        &mut self,
        frame: &GuardedDefaultCampaignWatchFrame,
    ) -> Result<(), GuardedCampaignRunSinkError> {
        self.watch_frames.push(frame.clone());
        Ok(())
    }
}
