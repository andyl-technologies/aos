//! Retains the native-side graph decoding prefix of an original import18.
//!
//! The two graph banks remain inert historical DATA. Completed SDK history,
//! Source closure, semantic spend and signed phase admissions remain separate
//! conjunctions; this attempt cannot produce the host-side sealed17 owner.

use super::*;
use std::mem::size_of;

/// Retains one native-side graph decoding attempt through original guard refusal.
///
/// Its private state preserves all initialized raw roles and decoder banks.
/// Decoding both graphs does not establish completed historical SDK outputs or
/// authorize restoration, target installation, Commit or execution.
pub struct RestoredSettledNative18GraphAttempt {
    decoded: Option<RestoredSettledNative17DecodeAttempt>,
    read_started: bool,
    guards_finished: bool,
    complete: bool,
}

impl RestoredSettledNative18GraphAttempt {
    /// Installs the original graph attempt before the first custody guard.
    ///
    /// The caller separately admits its inline layout; installation allocates
    /// no backing. An occupied destination always preserves its earlier owner.
    ///
    /// # Errors
    /// Refuses an occupied destination.
    pub(crate) fn begin_into_data(
        destination: &mut Option<Self>,
    ) -> Result<&mut Self, ProviderError> {
        if destination.is_some() {
            return Err(invalid());
        }
        *destination = Some(Self {
            decoded: None,
            read_started: false,
            guards_finished: false,
            complete: false,
        });
        destination.as_mut().ok_or_else(invalid)
    }

    /// Retains actual raw roles and both independently admitted decoder banks.
    ///
    /// Every refusal leaves initialized children in this spent attempt. This
    /// prefix does not authenticate completed historical SDK outputs.
    ///
    /// # Errors
    /// Refuses reuse, short constructor admission or decoder limits, allocation
    /// failure, malformed native graphs or incomplete selected targets.
    pub(crate) fn read_framed_with_admission_data(
        &mut self,
        plan: &RestoredSettledNative17Plan<'_>,
        maximum_target_requested: usize,
        admission: &dyn NativeCold17Admission,
    ) -> Result<(), ProviderError> {
        if self.read_started || self.guards_finished {
            return Err(invalid());
        }
        // Consume the attempt before admission or its first owning constructor.
        // No refusal can reset a partial graph bank for a second interpretation.
        self.read_started = true;
        let boundary = super::super::cold_admission::NativeCold17Boundary::new(admission);
        let scratch = Self::counter_scratch_data();
        boundary.begin_data(NativeCold17Work::RawInputs, 0, scratch)?;
        let raw = plan.raw_input_construction_bytes_data()?;
        boundary.construct_data(NativeCold17Work::RawInputs, raw, 0, scratch)?;

        plan.retain_decode_attempt_into(&mut self.decoded)?;
        let decoded = self.decoded.as_mut().ok_or_else(invalid)?;
        // The old reader's Validated discriminator requires real host SDK loans.
        // This distinct local prefix must never manufacture that discriminator.
        decoded.stage = super::super::sealed::DecodeStage::Failed;
        boundary.finish_data(
            NativeCold17Work::RawInputs,
            decoded.retained_requested_storage_data(plan.maximum_requested)?,
        )?;
        super::super::reader::read_graph_pair_with_admission_into_data(
            decoded,
            plan.maximum_requested,
            maximum_target_requested,
            plan.limits.maximum_nodes_data(),
            Some(&boundary),
        )?;
        super::super::reader::completed_graph_pair_data(decoded)?;
        Ok(())
    }

    /// Records graph DATA completion after the original and admission guards.
    ///
    /// Both success and refusal consume finalization without discarding any
    /// retained raw or typed prefix.
    ///
    /// # Errors
    /// Refuses repeated finalization, a failed guard outcome or incomplete graphs.
    pub(crate) fn finish_original_guards_data(
        &mut self,
        outcome: Result<(), ProviderError>,
    ) -> Result<(), ProviderError> {
        if self.guards_finished {
            return Err(invalid());
        }
        self.guards_finished = true;
        outcome?;
        let decoded = self.decoded.as_ref().ok_or_else(invalid)?;
        super::super::reader::completed_graph_pair_data(decoded)?;
        self.complete = true;
        Ok(())
    }

    /// Reports two decoded native graphs after their original bootstrap guards.
    ///
    /// This is graph DATA completion only. Historical output correspondence and
    /// full Source/semantic validation remain required before model adoption.
    pub const fn graphs_decoded_data(&self) -> bool {
        self.complete
    }

    /// Counts all retained raw and typed backing, including failed prefixes.
    ///
    /// The enclosing owner separately charges this attempt's inline layout and
    /// all seven original bootstrap banks. Existing graph counters include each
    /// decoder's raw copy, aliases, targets and actual partial allocations.
    ///
    /// # Errors
    /// Refuses invalid child capacity data, layout overflow or a short maximum.
    pub fn retained_requested_storage_data(&self, maximum: usize) -> Result<usize, ProviderError> {
        match &self.decoded {
            Some(decoded) => decoded.retained_requested_storage_data(maximum),
            None => Ok(0),
        }
    }

    /// Names the fixed native graph reader and original attempt controls.
    ///
    /// Dynamic banks, enclosing bootstrap guards and caller admission controls
    /// are separate terms. This value supplies no admission or phase permission.
    pub fn counter_scratch_data() -> usize {
        // The shared reader names its own parser, metadata and graph controls.
        // This wrapper adds only the borrowed plan/attempt and result controls.
        super::super::restored_settled_native17_counter_scratch_data()
            + size_of::<&mut Self>()
            + size_of::<&RestoredSettledNative17Plan<'static>>()
            + size_of::<&dyn NativeCold17Admission>()
            + size_of::<super::super::cold_admission::NativeCold17Boundary<'static>>()
            + size_of::<Result<(), ProviderError>>() * 3
            + size_of::<Result<usize, ProviderError>>()
            + size_of::<Result<&RestoredSettledNative17DecodeAttempt, ProviderError>>()
            + size_of::<Result<&mut RestoredSettledNative17DecodeAttempt, ProviderError>>()
            + size_of::<usize>() * 2
    }
}

#[cfg(test)]
#[path = "native_pair18_tests.rs"]
mod tests;
