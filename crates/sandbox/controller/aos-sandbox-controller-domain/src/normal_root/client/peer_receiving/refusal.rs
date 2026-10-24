//! Retains the sole prepaid negative Root peer/clock observation body.
//!
//! A genuine caller funds this native destination before a later financial
//! refusal. Its invocation has no healthy-loan gate, performs no late debit,
//! grants no positive token, and never resets an entered native leaf.

use std::error::Error;
use aos_sandbox_model::RawPairedClockSample;
use crate::policy_compiler::RetainedKernelPairedClockAttemptV1;
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::normal_root::{NormalRootStartupErrorV1, ProductionControllerNormalRootProfileV1};
use super::{StableRootPeerV1, sample::PeerSampleV1};

pub(in crate::normal_root::client) struct RootPeerRefusalOriginalV1 {
    peer: PeerSampleV1,
    returned: Option<Result<(), NormalRootStartupErrorV1>>,
    clock: RetainedKernelPairedClockAttemptV1,
    sample: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    entered: bool,
}

impl RootPeerRefusalOriginalV1 {
    pub(in crate::normal_root::client) fn new() -> Self {
        Self { peer: PeerSampleV1::new(), returned: None,
            clock: Default::default(), sample: None, entered: false }
    }

    pub(in crate::normal_root::client) fn observe_once(&mut self, profile: &ProductionControllerNormalRootProfileV1,
        stream: &aos_linux_descriptors::unix_stream::RetainedUnixStream,
        stable: Option<&StableRootPeerV1>, origin: RawPairedClockSample, cutoff: u64,
    ) {
        if self.entered { return; }
        self.entered = true;
        // This is already paid negative-only native custody. No healthy C23
        // debit, original-currentness or body-success gate can suppress it.
        self.returned = Some(self.peer.observe_with_cutoff_once_v1(
            profile, stream, stable, None, true, cutoff));
        self.sample = Some(self.clock.observe_once(Some(origin)));
    }

    pub(in crate::normal_root::client) fn property_failure_view_v1(&self)
        -> Option<aos_systemd_client::FixedPid1PropertyFailureViewV1<'_>> {
        self.peer.property_failure_view_v1()
    }

    pub(in crate::normal_root::client) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.peer.failure().or_else(|| cause(&self.returned))
            .or_else(|| self.clock.failure()).or_else(|| cause(&self.sample))
    }
}


fn cause<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}
