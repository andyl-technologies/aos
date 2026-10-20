//! Retains one paid Root subject chunk through its actual native posts.
//!
//! The D and provisioning callers select their own closed financial purpose.
//! This mechanical leaf has no payer or role constructor. Its held first
//! sample, credentialled payload, late cutoff and native disposal order are
//! shared; any failure remains resident with the cumulative byte buffer.

use std::error::Error;
use super::peer_receiving::sample::PeerSampleV1;
use super::{ProductionControllerNormalRootProfileV1, NormalRootStartupErrorV1};
use crate::policy_compiler::{RootSubjectReadinessV1, bounded_stream_io::remaining};
use aos_sandbox_linux::unix_stream::{RetainedUnixStream, RetainedSubjectStreamReadV1,
    SubjectStreamReadErrorV1};
use aos_sandbox_protocol::domain_ledger::create_storage_history::HistoryErrorV1;

#[derive(Default)]
pub(super) struct RootStrictChunkOriginalV1 {
    wait: RootSubjectReadinessV1,
    received: Option<Result<(), SubjectStreamReadErrorV1>>,
    sample: Option<Box<PeerSampleV1>>,
    subject: Option<Result<(), NormalRootStartupErrorV1>>,
    copy: Option<Result<(), SubjectStreamReadErrorV1>>,
    clock: Option<rustix::time::Timespec>,
    cutoff: Option<Result<std::time::Duration, HistoryErrorV1>>,
    settlement: Option<Result<(), NormalRootStartupErrorV1>>,
    retired: Option<Result<(), SubjectStreamReadErrorV1>>,
}

impl RootStrictChunkOriginalV1 {
    pub(super) fn failure<'cause>(
        &'cause self,
        buffer: &'cause RetainedSubjectStreamReadV1,
    ) -> Option<&'cause (dyn Error + 'static)> {
        self.wait
            .failure()
            .or_else(|| buffer.failure())
            .or_else(|| cause(&self.received))
            .or_else(|| self.sample.as_ref().and_then(|sample| sample.failure()))
            .or_else(|| cause(&self.subject))
            .or_else(|| cause(&self.copy))
            .or_else(|| cause(&self.cutoff))
            .or_else(|| cause(&self.settlement))
            .or_else(|| cause(&self.retired))
    }

    pub(super) fn property_failure_view_v1(&self)
        -> Option<aos_systemd_client::FixedPid1PropertyFailureViewV1<'_>> {
        self.sample.as_ref()?.property_failure_view_v1()
    }

    pub(super) fn receive_once(
        &mut self,
        buffer: &mut RetainedSubjectStreamReadV1,
        stream: &mut RetainedUnixStream,
        anchor: &PeerSampleV1,
        profile: &ProductionControllerNormalRootProfileV1,
        geometry: &aos_sandbox_linux::unix_stream::SubjectStreamReceiveGeometryV1,
        cutoff: u64,
    ) -> Result<(), HistoryErrorV1> {
        if !self
            .wait
            .wait_retained_once_v1(&*stream, cutoff)
        {
            return Err(HistoryErrorV1::Correlation);
        }
        self.received = Some(buffer.receive_next_with_geometry_once(
            &mut *stream,
            geometry,
        ));
        if matches!(self.received, Some(Ok(()))) {
            self.sample = Some(Box::new(PeerSampleV1::new()));
            self.subject = Some(
                self
                    .sample
                    .as_mut()
                    .ok_or(HistoryErrorV1::Correlation)?
                    .observe_against_sample_with_cutoff_once_v1(
                        profile,
                        &*stream,
                        anchor,
                        Some(buffer.pending_chunk().map_err(|_| HistoryErrorV1::Correlation)?),
                        false,
                        cutoff,
                    ),
            );
            if matches!(self.subject, Some(Ok(()))) {
                self.copy = Some(buffer.append_pending_payload_once());
            }
        }
        // The actual trailing cutoff is parked after every reached native
        // receive/subject/copy result, even if that earlier result refused.
        let after = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
        self.clock = Some(after);
        self.cutoff = Some(remaining(after, cutoff));
        if !matches!(self.received, Some(Ok(())))
            || !matches!(self.subject, Some(Ok(())))
            || !matches!(self.copy, Some(Ok(())))
            || !matches!(self.cutoff, Some(Ok(_)))
        {
            return Err(HistoryErrorV1::Correlation);
        }
        self.settlement = Some(
            self
                .sample
                .as_mut()
                .ok_or(HistoryErrorV1::Correlation)?
                .settle_positive_once(),
        );
        if !matches!(self.settlement, Some(Ok(()))) {
            return Err(HistoryErrorV1::Correlation);
        }
        self.retired = Some(buffer.take_copied_chunk_once().map(drop));
        if !matches!(self.retired, Some(Ok(()))) {
            return Err(HistoryErrorV1::Correlation);
        }
        Ok(())
    }
}

fn cause<T,E:Error+'static>(slot:&Option<Result<T,E>>)->Option<&(dyn Error+'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}
