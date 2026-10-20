//! Owns the sole D strict message receiver and its retained native chunk causes.
//!
//! The challenge already funded this actual bounded buffer and one chunk peak.
//! Each reached chunk independently pays its complete currentness traffic before
//! arming. These bytes remain comparison DATA; no batch can mint C17/six cuts.

use std::error::Error as StdError;
use std::os::unix::net::UnixStream;

use super::super::{RootDeleteChallengeOriginalsV1, RootDeleteErrorV1};
use crate::normal_root::{RootControllerChunkSubjectSampleV1, RootPolicyAcceptedFlightV1};
use crate::policy_compiler::root_subject_chunk::RootSubjectChunkReceivingV1;
use aos_sandbox_linux::{
    seqpacket::SeqpacketError,
    unix_stream::{
        RetainedSubjectStreamReadV1, SubjectStreamReadErrorV1, SubjectStreamReceiveGeometryV1,
    },
};

#[derive(Clone, Copy)]
enum Reporting {
    Enable,
    AlreadyEnabled,
}

#[derive(Clone, Copy)]
enum First {
    Geometry,
    Reporting,
    Preparation,
    Chunk,
    Reentry,
}

pub(in crate::policy_compiler::delete_root) struct RootDeleteMessageReceivingV2 {
    geometry: Result<SubjectStreamReceiveGeometryV1, SeqpacketError>,
    reporting: Option<Result<(), SeqpacketError>>,
    preparation: Option<Result<(), SubjectStreamReadErrorV1>>,
    buffer: RetainedSubjectStreamReadV1,
    chunk: RootSubjectChunkReceivingV1,
    receiving: Option<Result<(), crate::policy_compiler::RootCreateStorageCurrentErrorV1>>,
    first: Option<First>,
    entered: bool,
    closed: Option<RootDeleteErrorV1>,
}

impl Default for RootDeleteMessageReceivingV2 {
    fn default() -> Self {
        Self {
            geometry: RootControllerChunkSubjectSampleV1::receive_geometry_v1(),
            reporting: None,
            preparation: None,
            buffer: RetainedSubjectStreamReadV1::new(),
            chunk: Default::default(),
            receiving: None,
            first: None,
            entered: false,
            closed: None,
        }
    }
}

impl RootDeleteMessageReceivingV2 {
    pub(in crate::policy_compiler::delete_root) fn receive_once_v1(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        original: &UnixStream,
        challenge: &RootDeleteChallengeOriginalsV1,
        length: usize,
    ) -> Result<(), RootDeleteErrorV1> {
        self.receive_inner(flight, original, challenge, length, Reporting::Enable)
    }

    pub(in crate::policy_compiler::delete_root) fn receive_continuation_once_v2(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        original: &UnixStream,
        challenge: &RootDeleteChallengeOriginalsV1,
        length: usize,
    ) -> Result<(), RootDeleteErrorV1> {
        self.receive_inner(
            flight,
            original,
            challenge,
            length,
            Reporting::AlreadyEnabled,
        )
    }

    fn receive_inner(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        original: &UnixStream,
        challenge: &RootDeleteChallengeOriginalsV1,
        length: usize,
        reporting: Reporting,
    ) -> Result<(), RootDeleteErrorV1> {
        if self.entered || self.closed.is_some() {
            self.first.get_or_insert(First::Reentry);
            self.closed.get_or_insert(RootDeleteErrorV1::Original);
            return Err(RootDeleteErrorV1::Original);
        }
        self.entered = true;
        challenge
            .require_paid_chunk_peak_v1()
            .map_err(|_| RootDeleteErrorV1::Opening)?;
        let Some(geometry) = self.geometry.as_ref().ok() else {
            self.first = Some(First::Geometry);
            return Err(RootDeleteErrorV1::Opening);
        };
        if matches!(reporting, Reporting::Enable) {
            self.reporting = Some(flight.enable_delete_subject_reporting_once_v1());
            if !matches!(self.reporting, Some(Ok(()))) {
                self.first = Some(First::Reporting);
                return Err(RootDeleteErrorV1::Opening);
            }
        }
        self.preparation = Some(self.buffer.prepare_exact_once(length));
        if !matches!(self.preparation, Some(Ok(()))) {
            self.first = Some(First::Preparation);
            return Err(RootDeleteErrorV1::Opening);
        }
        self.receiving = Some(self.chunk.receive_delete_exact_v1(
            flight,
            original,
            &mut self.buffer,
            geometry,
            challenge,
        ));
        if !matches!(self.receiving, Some(Ok(()))) {
            self.first = Some(First::Chunk);
            return Err(RootDeleteErrorV1::Opening);
        }
        Ok(())
    }

    pub(in crate::policy_compiler::delete_root) fn bytes_v2(
        &self,
    ) -> Result<&[u8], RootDeleteErrorV1> {
        if !self.entered || self.first.is_some() || !matches!(self.receiving, Some(Ok(()))) {
            return Err(RootDeleteErrorV1::Original);
        }
        Ok(self.buffer.bytes())
    }

    pub(in crate::policy_compiler::delete_root) fn financial_failure_is_selected_v1(&self) -> bool {
        matches!(self.first, Some(First::Chunk)) && self.chunk.financial_failure_is_selected_v1()
    }

    pub(in crate::policy_compiler::delete_root) fn property_failure_view_v1(
        &self,
    ) -> Option<aos_systemd::FixedPid1PropertyFailureViewV1<'_>> {
        if matches!(self.first, Some(First::Chunk)) {
            self.chunk.property_failure_view_v1(&self.buffer)
        } else {
            None
        }
    }

    pub(in crate::policy_compiler::delete_root) fn failure(
        &self,
    ) -> Option<&(dyn StdError + 'static)> {
        fn cause<T, E: StdError + 'static>(
            slot: &Option<Result<T, E>>,
        ) -> Option<&(dyn StdError + 'static)> {
            slot.as_ref()?.as_ref().err().map(|cause| cause as _)
        }
        match self.first? {
            First::Geometry => self.geometry.as_ref().err().map(|cause| cause as _),
            First::Reporting => cause(&self.reporting),
            First::Preparation => self.buffer.failure().or_else(|| cause(&self.preparation)),
            First::Chunk => self
                .chunk
                .failure_with_buffer(&self.buffer)
                .or_else(|| cause(&self.receiving)),
            First::Reentry => self.closed.as_ref().map(|cause| cause as _),
        }
    }
}
