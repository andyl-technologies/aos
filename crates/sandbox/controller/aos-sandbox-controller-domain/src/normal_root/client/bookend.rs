//! Shares the existing retained Root peer and paired-clock bookend recipe.
//!
//! Callers prepay each concrete destination on their actual Source. A native
//! after uses the same originals even after primary refusal; this mechanical
//! owner neither selects a payer nor supplies a purpose or positive grant.

use std::error::Error;

use aos_sandbox_model::RawPairedClockSample;
use aos_linux_descriptors::unix_stream::RetainedUnixStream;
use aos_sandbox_protocol::domain_ledger::create_storage_history::HistoryErrorV1;

use super::{
    NormalRootStartupErrorV1, ProductionControllerNormalRootProfileV1,
    peer_receiving::sample::PeerSampleV1,
};
use crate::{
    hierarchy::genesis_profile::SourceGenesisErrorV1,
    policy_compiler::RetainedKernelPairedClockAttemptV1,
};

pub(super) struct RootClientBookendV1 {
    pub(super) peer: Box<PeerSampleV1>,
    pub(super) observed: Option<Result<(), NormalRootStartupErrorV1>>,
    pub(super) clock: RetainedKernelPairedClockAttemptV1,
    pub(super) sample: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    pub(super) time: Option<Result<(), HistoryErrorV1>>,
}

impl RootClientBookendV1 {
    pub(super) fn new() -> Self {
        Self {
            peer: Box::new(PeerSampleV1::new()),
            observed: None,
            clock: Default::default(),
            sample: None,
            time: None,
        }
    }

    /// Runs the same peer capture, then an independent clock despite refusal.
    /// The caller preserves its exact baseline selection; None captures anew.
    pub(super) fn observe_once(
        &mut self,
        profile: &ProductionControllerNormalRootProfileV1,
        stream: Option<&RetainedUnixStream>,
        baseline: Option<&Self>,
        origin: RawPairedClockSample,
        cutoff: u64,
        owed: bool,
    ) -> Result<(), HistoryErrorV1> {
        if self.sample.is_some() {
            return Err(HistoryErrorV1::Correlation);
        }
        if let Some(stream) = stream {
            self.observed = Some(match baseline {
                Some(before) => self.peer.observe_against_sample_with_cutoff_once_v1(
                    profile,
                    stream,
                    &before.peer,
                    None,
                    owed,
                    cutoff,
                ),
                None => self
                    .peer
                    .observe_with_cutoff_once_v1(profile, stream, None, None, owed, cutoff),
            });
        }
        self.sample = Some(self.clock.observe_once(Some(origin)));
        self.time = Some((|| {
            let sample = self
                .sample
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .copied()
                .ok_or(HistoryErrorV1::Malformed)?;
            origin
                .validate_later_sample(sample)
                .map_err(|_| HistoryErrorV1::Malformed)?;
            if sample.boottime_nanoseconds() >= cutoff {
                return Err(HistoryErrorV1::Malformed);
            }
            Ok(())
        })());
        if !matches!(self.observed, Some(Ok(()))) || !matches!(self.time, Some(Ok(()))) {
            return Err(HistoryErrorV1::Correlation);
        }
        Ok(())
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.peer
            .failure()
            .or_else(|| error(&self.observed))
            .or_else(|| self.clock.failure())
            .or_else(|| error(&self.sample))
            .or_else(|| error(&self.time))
    }
}

fn error<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}
