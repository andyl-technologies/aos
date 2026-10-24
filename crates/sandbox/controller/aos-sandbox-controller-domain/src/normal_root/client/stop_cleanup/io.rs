//! Uses the shared Root stream, native bookends and cumulative Source22 payer.

use super::*;

impl RootStopCleanupClientOriginalV1 {
    pub(super) fn demand(
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<ResourceVector, ResourceReservationErrorV1> {
        let bad = || ResourceReservationErrorV1::Conflict;
        let native = CreateStorageRootPeerReceivingOriginalsV1::retained_bookends_native_peak_v1(
            profile, BOOKENDS,
        )
        .ok_or_else(bad)?;
        let geometry = CreateStorageRootPeerReceivingOriginalsV1::receiving_geometry_v1()
            .map_err(|_| bad())?;
        let (raw, files) = geometry.receive_obligations_v1();
        // Eight concrete peer/clock bookends and one separately retained
        // presign clock. No after depends on a new financial or healthy gate.
        let clocks = BOOKENDS.checked_add(1).ok_or_else(bad)?;
        let bytes = size_of::<Self>()
            .checked_add(size_of::<Native>())
            .and_then(|n| {
                n.checked_add(size_of::<RootStopCleanupSigningLoanV1<'_, '_, '_>>().checked_mul(2)?)
            })
            .and_then(|n| {
                n.checked_add(size_of::<RootStopCleanupChildLoanV1<'_>>().checked_mul(2)?)
            })
            .and_then(|n| {
                n.checked_add(
                    size_of::<RootStopCleanupClientCompletedBorrowV1<'_>>().checked_mul(2)?,
                )
            })
            .and_then(|n| n.checked_add(size_of::<OwedAfter<'_>>().checked_mul(2)?))
            .and_then(|n| n.checked_add(size_of::<RootStrictChunkOriginalV1>().checked_mul(2)?))
            .and_then(|n| n.checked_add(size_of::<RootClientFundingV1<'_>>().checked_mul(2)?))
            .and_then(|n| n.checked_add(size_of::<RootReplyReceiveV1<'_>>().checked_mul(2)?))
            .and_then(|n| n.checked_add(raw))
            .and_then(|n| {
                n.checked_add(
                    RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()?
                        .checked_mul(clocks)?,
                )
            })
            .and_then(|n| n.checked_add(stop_cleanup_digest_receiving_bytes_v1()?))
            // The raw first reply is priced dynamically by the common loop.
            // Comparison ACK, final receipt and confirmation remain resident.
            .and_then(|n| {
                n.checked_add(
                    RECEIPT_BYTES_V1
                        .checked_add(48)?
                        .checked_add(DECISION_BYTES_V1)?
                        .checked_mul(3)?,
                )
            })
            .and_then(|n| n.checked_mul(3))
            .and_then(|n| u64::try_from(n).ok())
            .ok_or_else(bad)?;
        let files = RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1
            .checked_mul(clocks)
            .and_then(|n| n.checked_add(files))
            .and_then(|n| u64::try_from(n).ok())
            .ok_or_else(bad)?;
        let names = RetainedKernelPairedClockAttemptV1::receiving_metadata_cells_v1()
            .and_then(|n| n.checked_mul(clocks))
            .and_then(|n| u64::try_from(n).ok())
            .ok_or_else(bad)?;
        Ok(native
            .checked_add(
                ControllerRootConnectionOriginalV1::receiving_demand_v1().ok_or_else(bad)?,
            )?
            .checked_add(
                ResourceVector::ZERO
                    .with(D::MemoryBytes, bytes)
                    .with(D::OpenFiles, files)
                    .with(D::MetadataEntries, names),
            )?)
    }

    pub(super) fn charge(
        &mut self,
        source: &mut Source<'_, '_>,
        controller: &Journal,
        wire: usize,
        output: usize,
    ) -> Result<(), RootStopCleanupClientClosedV1> {
        let mut funding = RootClientFundingV1 {
            complete: self.complete,
            observations: &mut self.observations,
            wire: &mut self.wire,
            output: &mut self.output,
            received_bound: &mut self.received_bound,
            admission: &mut self.admission,
            funding_original: &mut self.funding_original,
        };
        if funding
            .charge(
                &mut RootClientLoanV1::StopCleanup(source),
                controller,
                0,
                wire,
                output,
            )
            .is_err()
        {
            self.first.get_or_insert(First::Funding);
            return Err(RootStopCleanupClientClosedV1);
        }
        Ok(())
    }

    pub(super) fn add_demand(
        &mut self,
        source: &mut Source<'_, '_>,
        controller: &Journal,
        demand: ResourceVector,
    ) -> Result<(), Cause> {
        self.complete = self.complete.checked_add(demand)?;
        self.charge(source, controller, 0, 0)?;
        Ok(())
    }

    pub(super) fn receive(
        &mut self,
        source: &mut Source<'_, '_>,
        controller: &Journal,
        index: usize,
        purpose: Option<RootReplyPurposeV1>,
    ) -> Result<(), Cause> {
        let native = self.native.as_mut().ok_or(RootStopCleanupClientClosedV1)?;
        let reply = native
            .replies
            .get_mut(index)
            .ok_or(RootStopCleanupClientClosedV1)?;
        let mut receive = RootReplyReceiveV1 {
            connection: &mut native.connection,
            received: &mut reply.received,
            preparation: &mut reply.preparation,
            extension: &mut reply.extension,
            chunk: &mut reply.chunk,
            data_failure: &mut native.data_failure,
            peer_before: &native.bookends[0].peer,
            profile: &native.profile,
            cutoff: native.cutoff,
        };
        let mut funding = RootClientFundingV1 {
            complete: self.complete,
            observations: &mut self.observations,
            wire: &mut self.wire,
            output: &mut self.output,
            received_bound: &mut self.received_bound,
            admission: &mut self.admission,
            funding_original: &mut self.funding_original,
        };
        let mut loan = RootClientLoanV1::StopCleanup(source);
        let result = match purpose {
            Some(purpose) => receive.receive_reply(purpose, &mut loan, controller, &mut funding),
            None => receive.receive_fixed_reply_v2(
                aos_sandbox_protocol::root_policy_completion::ROOT_POLICY_POSITIVE_COMPLETION_BYTES_V2,
                &mut loan, controller, &mut funding),
        };
        result.map_err(|_| Box::new(RootStopCleanupClientClosedV1) as Cause)
    }

    pub(super) fn receive_child_comparison(
        &mut self,
        source: &mut Source<'_, '_>,
        controller: &Journal,
    ) -> Result<(), Cause> {
        // The fixed fourth destination and its complete extent are paid before
        // growth. This ACK is Root's genuine comparison, not financial Dpositive.
        self.charge(source, controller, DECISION_HEADER_BYTES_V1, 0)?;
        self.receive(
            source,
            controller,
            3,
            Some(RootReplyPurposeV1::StopDecision),
        )?;
        let native = self.native.as_mut().ok_or(RootStopCleanupClientClosedV1)?;
        native.comparison = Some((|| {
            let frame =
                StopCleanupObservedDecisionDataV1::decode_v1(native.replies[3].received.bytes())?;
            if frame.query_digest != native.query_digest
                || frame.decision_digest != native.decision_digest
            {
                return Err(HistoryErrorV1::Correlation);
            }
            Ok(())
        })());
        positive(&native.comparison)?;
        Ok(())
    }

    pub(super) fn observe_bookend(
        &mut self,
        index: usize,
        profile: &ProductionControllerNormalRootProfileV1,
        owed: bool,
    ) -> Result<(), RootStopCleanupClientClosedV1> {
        let native = self.native.as_mut().ok_or(RootStopCleanupClientClosedV1)?;
        if native.bookends[index].sample.is_some() {
            return Err(self.refuse_reentry());
        }
        let stream = native.connection.stream().ok();
        let result = if index == 0 {
            native.bookends[0].observe_once(
                profile,
                stream,
                None,
                native.origin,
                native.cutoff,
                owed,
            )
        } else {
            let (previous, current) = native.bookends.split_at_mut(index);
            let before = matches!(previous[0].observed, Some(Ok(()))).then_some(&previous[0]);
            current[0].observe_once(profile, stream, before, native.origin, native.cutoff, owed)
        };
        if result.is_err() {
            self.first.get_or_insert(First::Bookend(index));
            return Err(RootStopCleanupClientClosedV1);
        }
        // This additional pure restriction is kept separately from the
        // shared mechanical original-D comparison, preserving its own cause.
        let sample = *positive(&native.bookends[index].sample)?;
        if sample.wall_seconds() >= native.expiry {
            native.bookends[index].time = Some(Err(HistoryErrorV1::Malformed));
            self.first.get_or_insert(First::Bookend(index));
            return Err(RootStopCleanupClientClosedV1);
        }
        Ok(())
    }

    pub(super) fn drain_owed(
        &mut self,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), RootStopCleanupClientClosedV1> {
        let index = self.pending.take().ok_or(RootStopCleanupClientClosedV1)?;
        self.observe_bookend(index, profile, true)
    }
}
