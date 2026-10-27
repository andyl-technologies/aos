//! Campaign progress the CLI renders after a guarded run completes.
//!
//! The daemon streams accepted observations and watch frames to a sink
//! instead of retaining them. [`CampaignRunProgress`] keeps only what the run
//! output contract prints: one canonical-log summary per observation and,
//! when watch output was requested, the watch frames themselves.

use super::*;

/// One accepted observation reduced to its canonical-log line.
pub(crate) struct CampaignObservationLine {
    pub(crate) virtual_time_ticks: u64,
    pub(crate) summary: String,
}

/// Sink that keeps the printed projection of a guarded campaign's progress.
#[derive(Default)]
pub(crate) struct CampaignRunProgress {
    observations: Vec<CampaignObservationLine>,
    watch_frames: Vec<GuardedDefaultCampaignWatchFrame>,
}

impl CampaignRunProgress {
    /// Returns the canonical-log line of each accepted observation, in order.
    pub(crate) fn observations(&self) -> &[CampaignObservationLine] {
        &self.observations
    }

    /// Returns every delivered watch frame, in order.
    pub(crate) fn watch_frames(&self) -> &[GuardedDefaultCampaignWatchFrame] {
        &self.watch_frames
    }
}

impl GuardedCampaignRunSink for CampaignRunProgress {
    fn on_observation(
        &mut self,
        accepted: &GuardedDefaultCampaignObservation,
    ) -> Result<(), GuardedCampaignRunSinkError> {
        let ordinal = self.observations.len();
        self.observations.push(CampaignObservationLine {
            virtual_time_ticks: accepted.virtual_time_ticks(),
            summary: format!(
                "ordinal={} observation={} attempt={} child={} stop={}",
                ordinal,
                accepted.id(),
                accepted.observation().attempt(),
                accepted.observation().child(),
                campaign_stop_label(accepted.observation().stop()),
            ),
        });
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
