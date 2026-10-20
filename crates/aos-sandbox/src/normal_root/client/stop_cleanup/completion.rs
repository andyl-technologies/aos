//! Keeps Root custody around the real child and verifies post-disposal completion.

use super::*;
use aos_sandbox_protocol::root_policy_completion::{
    ROOT_POLICY_POSITIVE_COMPLETION_BYTES_V2, stop_cleanup_positive_completion_bytes_v1,
};

/// Holds the actual Root connection during Host1 and the independent final Host3.
///
/// Source22 is reborrowed by the SDK while this owner retains Root native
/// custody. Observed completion supplies no signed Host1 effect.
#[must_use = "finish the independently prepaid Root child after"]
pub struct RootStopCleanupChildLoanV1<'root> {
    guard: OwedAfter<'root>,
    finished: bool,
}

/// Borrows only a completed physical Root exchange, with no scalar constructor.
///
/// Every comparison getter requires genuine Root48, exact EOF and all actual
/// native posts. The enclosing Source22 currentness remains a separate join.
///
/// ```compile_fail
/// use aos_sandbox::normal_root::{RootStopCleanupClientCompletedBorrowV1,
///     RootStopCleanupClientOriginalV1};
/// fn forge(original: &RootStopCleanupClientOriginalV1) {
///     let _completion = RootStopCleanupClientCompletedBorrowV1 { owner: original };
/// }
/// ```
pub struct RootStopCleanupClientCompletedBorrowV1<'root> {
    owner: &'root RootStopCleanupClientOriginalV1,
}

impl RootStopCleanupClientOriginalV1 {
    /// Retains the Root peer around the actual child on the same Source22.
    ///
    /// # Errors
    /// Refuses another phase or payer. An observed decision sends only its
    /// explicit signature-free acknowledgement; no Host1 grant is produced.
    pub fn begin_child_once_v1<'root>(
        &'root mut self,
        source: &mut Source<'_, '_>,
        controller: &Journal,
    ) -> Result<RootStopCleanupChildLoanV1<'root>, RootStopCleanupClientClosedV1> {
        let observed = self
            .native
            .as_ref()
            .ok_or(RootStopCleanupClientClosedV1)?
            .observed;
        if observed {
            if self.require_phase(1).is_err() {
                return Err(self.refuse_reentry());
            }
            let profile = Arc::clone(
                &self
                    .native
                    .as_ref()
                    .ok_or(RootStopCleanupClientClosedV1)?
                    .profile,
            );
            self.pending = Some(3);
            let mut guard = OwedAfter {
                owner: self,
                profile,
            };
            let result = guard.owner.observe_decision_body(source, controller);
            guard.owner.record_body(1, result);
            guard.finish();
            drop(guard);
            if self.first.is_some() {
                return Err(RootStopCleanupClientClosedV1);
            }
            self.phase = 2;
        }
        if self.require_phase(2).is_err() {
            return Err(self.refuse_reentry());
        }
        if !matches!(
            self.native
                .as_ref()
                .and_then(|native| native.comparison.as_ref()),
            Some(Ok(()))
        ) {
            return Err(self.retain_validation(Box::new(RootStopCleanupClientClosedV1)));
        }
        self.validate_source(source, controller)?;
        let profile = Arc::clone(
            &self
                .native
                .as_ref()
                .ok_or(RootStopCleanupClientClosedV1)?
                .profile,
        );
        self.pending = Some(5);
        let guard = OwedAfter {
            owner: self,
            profile,
        };
        let before = guard.owner.observe_bookend(4, &guard.profile, false);
        if before.is_ok() && !observed {
            let result = guard.owner.prepare_child_effect(source, controller);
            if result.is_err() {
                guard.owner.first.get_or_insert(First::Signing);
            }
            if let Some(local) = guard
                .owner
                .native
                .as_mut()
                .and_then(|native| native.signing.as_mut())
            {
                local.effect = Some(result);
            }
        }
        // The typed borrower is returned after entry even on refusal so its
        // prepaid after is not lost through an early question-mark return.
        Ok(RootStopCleanupChildLoanV1 {
            guard,
            finished: false,
        })
    }

    fn observe_decision_body(
        &mut self,
        source: &mut Source<'_, '_>,
        controller: &Journal,
    ) -> Result<(), Cause> {
        self.require_source(source, controller)?;
        let profile = Arc::clone(
            &self
                .native
                .as_ref()
                .ok_or(RootStopCleanupClientClosedV1)?
                .profile,
        );
        self.observe_bookend(2, &profile, false)?;
        let native = self.native.as_ref().ok_or(RootStopCleanupClientClosedV1)?;
        let frame = StopCleanupObservedDecisionDataV1 {
            query_digest: &native.query_digest,
            decision_digest: &native.decision_digest,
        };
        let bytes = frame.encoded_bytes_v1()?;
        self.charge(source, controller, bytes, bytes)?;
        let native = self.native.as_mut().ok_or(RootStopCleanupClientClosedV1)?;
        let frame = StopCleanupObservedDecisionDataV1 {
            query_digest: &native.query_digest,
            decision_digest: &native.decision_digest,
        };
        resource_stream::send_subject_v1(
            RootSubjectDataV1::StopObservedDecision(frame),
            &mut native.connection,
            &mut native.sender[1],
            &mut native.sent[1],
            &mut native.scratch,
            &mut native.data_failure,
            native.cutoff,
        )
        .map_err(|_| RootStopCleanupClientClosedV1)?;
        self.receive_child_comparison(source, controller)?;
        Ok(())
    }

    fn prepare_child_effect(
        &mut self,
        source: &mut Source<'_, '_>,
        controller: &Journal,
    ) -> Result<crate::PreparedAuthorityEffectV1, Cause> {
        self.require_source(source, controller)?;
        // Signing populated the cached projection. Reuse only requires its
        // same protected row; the retained body remains the sole construction.
        source.current_desired_generation_data_v1(controller)?;
        let body_bytes = self
            .native
            .as_ref()
            .and_then(|native| native.signing.as_ref())
            .and_then(|local| local.deadline_free_body.as_ref())
            .ok_or(RootStopCleanupClientClosedV1)?
            .len();
        let clone_bytes = body_bytes
            .checked_mul(3)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(HistoryErrorV1::Extent)?;
        self.add_demand(
            source,
            controller,
            ResourceVector::ZERO.with(D::MemoryBytes, clone_bytes),
        )?;
        let native = self.native.as_mut().ok_or(RootStopCleanupClientClosedV1)?;
        let local = native
            .signing
            .as_mut()
            .ok_or(RootStopCleanupClientClosedV1)?;
        positive(&local.sent)?;
        let selected = local
            .selected
            .as_ref()
            .ok_or(RootStopCleanupClientClosedV1)?;
        let prepared = local
            .preparation
            .as_ref()
            .ok_or(RootStopCleanupClientClosedV1)?;
        let sample = *positive(&native.bookends[4].sample)?;
        // The sole current-generation producer retained both legitimate forms:
        // deadline-free template bytes and the prepared live request.
        let body = local
            .deadline_free_body
            .as_ref()
            .ok_or(RootStopCleanupClientClosedV1)?
            .clone();
        let template = aos_sandbox_protocol::decode_runtime_template_v1(&body)?;
        let semantics =
            aos_sandbox_protocol::semantics::host::canonical_host_template_semantics_v1(&template)?;
        let template = aos_sandbox_protocol::dispatch_template::BrokerDispatchTemplateV1::new(
            local
                .signed
                .as_ref()
                .ok_or(RootStopCleanupClientClosedV1)?
                .clone(),
            aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME,
            body,
            Vec::new(),
            aos_sandbox_protocol::dispatch_template::BrokerDispatchSemanticIdentityV1::new(
                semantics.verb(),
                semantics.target(),
                semantics.commitment(),
            ),
        )?;
        let attempt = crate::BrokerDispatchAttemptV1::new(
            &template,
            local.lease.value().ok_or(RootStopCleanupClientClosedV1)?,
            native.cutoff,
            sample,
        )?;
        if attempt.body() != prepared.request_body.as_slice() {
            return Err(HistoryErrorV1::Correlation.into());
        }
        Ok(crate::PreparedAuthorityEffectV1::new(
            selected.binding.digest(),
            selected.binding.publication_digest(),
            sample,
            attempt,
        ))
    }

    /// Sends the genuine second fresh Host3 reference and awaits physical Root completion.
    ///
    /// # Errors
    /// Refuses unfinished child posts, another Source, reused Host3, changed
    /// receipt, incomplete Root48, hostile EOF or any independent native post.
    pub fn finish_once_v1(
        &mut self,
        source: &mut Source<'_, '_>,
        controller: &Journal,
    ) -> Result<(), RootStopCleanupClientClosedV1> {
        if self.require_phase(3).is_err() {
            return Err(self.refuse_reentry());
        }
        let profile = Arc::clone(
            &self
                .native
                .as_ref()
                .ok_or(RootStopCleanupClientClosedV1)?
                .profile,
        );
        self.pending = Some(7);
        let mut guard = OwedAfter {
            owner: self,
            profile,
        };
        let result = guard.owner.finish_body(source, controller);
        guard.owner.record_body(2, result);
        guard.finish();
        drop(guard);
        if self.first.is_some() {
            return Err(RootStopCleanupClientClosedV1);
        }
        self.phase = 4;
        Ok(())
    }

    fn finish_body(
        &mut self,
        source: &mut Source<'_, '_>,
        controller: &Journal,
    ) -> Result<(), Cause> {
        self.require_source(source, controller)?;
        let host = source.completed_host_inventory_reference_data_v1(controller, 1)?;
        let native = self.native.as_mut().ok_or(RootStopCleanupClientClosedV1)?;
        if host.0 == native.opening.host.0 || host.1 != native.opening.host.1 {
            return Err(HistoryErrorV1::Correlation.into());
        }
        native.final_host = Some(host);
        let profile = Arc::clone(&native.profile);
        self.observe_bookend(6, &profile, false)?;
        let native = self.native.as_ref().ok_or(RootStopCleanupClientClosedV1)?;
        let frame = StopCleanupFinalDataV1 {
            query_digest: &native.query_digest,
            host_query: &host.0,
            host_session: &host.1,
            host_request: &host.2,
            host_outcome: &host.3,
            host_body: &host.4,
        };
        let bytes = frame.encoded_bytes_v1()?;
        self.charge(
            source,
            controller,
            bytes
                .checked_add(RECEIPT_HEADER_BYTES_V1)
                .and_then(|n| n.checked_add(1))
                .ok_or(HistoryErrorV1::Extent)?,
            bytes,
        )?;
        let native = self.native.as_mut().ok_or(RootStopCleanupClientClosedV1)?;
        let frame = StopCleanupFinalDataV1 {
            query_digest: &native.query_digest,
            host_query: &host.0,
            host_session: &host.1,
            host_request: &host.2,
            host_outcome: &host.3,
            host_body: &host.4,
        };
        resource_stream::send_subject_v1(
            RootSubjectDataV1::StopFinal(frame),
            &mut native.connection,
            &mut native.sender[2],
            &mut native.sent[2],
            &mut native.scratch,
            &mut native.data_failure,
            native.cutoff,
        )
        .map_err(|_| RootStopCleanupClientClosedV1)?;
        self.receive(source, controller, 1, Some(RootReplyPurposeV1::StopReceipt))?;
        let native = self.native.as_ref().ok_or(RootStopCleanupClientClosedV1)?;
        let receipt = StopCleanupReceiptDataV1::decode_v1(native.replies[1].received.bytes())?;
        if receipt.query_digest != native.query_digest
            || receipt.decision_digest != native.decision_digest
            || receipt.terminal_host_outcome != host.3
            || receipt.cutoff != native.cutoff.to_be_bytes()
        {
            return Err(HistoryErrorV1::Correlation.into());
        }
        self.receive(source, controller, 2, None)?;
        let native = self.native.as_mut().ok_or(RootStopCleanupClientClosedV1)?;
        let expected = stop_cleanup_positive_completion_bytes_v1(
            native.query_digest,
            native.decision_digest,
            host.3,
        );
        native.confirmation = Some(if native.replies[2].received.bytes() == expected {
            Ok(())
        } else {
            Err(HistoryErrorV1::Correlation)
        });
        positive(&native.confirmation)?;
        native.ended = Some(native.eof.run_once(
            native.connection.stream_mut()?,
            &mut native.eof_byte,
            native.cutoff,
            DeadlineStreamDirectionV1::Eof,
        ));
        positive(&native.ended)?;
        if !native.eof.completed_exact() {
            return Err(HistoryErrorV1::Correlation.into());
        }
        Ok(())
    }

    fn require_completed(&self) -> Result<&Native, RootStopCleanupClientClosedV1> {
        self.require_phase(4)?;
        let native = self
            .native
            .as_deref()
            .ok_or(RootStopCleanupClientClosedV1)?;
        if !matches!(native.confirmation, Some(Ok(())))
            || !matches!(native.comparison, Some(Ok(())))
            || !matches!(native.ended, Some(Ok(())))
            || !native.eof.completed_exact()
            || self.body.iter().any(|value| !matches!(value, Some(Ok(()))))
            || native.bookends.iter().any(|one| {
                !matches!(one.observed, Some(Ok(())))
                    || !matches!(one.time, Some(Ok(())))
                    || !matches!(one.sample, Some(Ok(_)))
            })
        {
            return Err(RootStopCleanupClientClosedV1);
        }
        Ok(native)
    }

    /// Borrows completion only after exact48, EOF and every actual Root post.
    ///
    /// # Errors
    /// Refuses an incomplete exchange or changed same-Source22/final Host3 association.
    pub fn borrow_completed_once_v1<'root>(
        &'root self,
        source: &Source<'_, '_>,
        controller: &Journal,
    ) -> Result<RootStopCleanupClientCompletedBorrowV1<'root>, RootStopCleanupClientClosedV1> {
        let native = self.require_completed()?;
        self.require_source(source, controller)
            .map_err(|_| RootStopCleanupClientClosedV1)?;
        if source
            .completed_host_inventory_reference_data_v1(controller, 1)
            .map_err(|_| RootStopCleanupClientClosedV1)?
            != native.final_host.ok_or(RootStopCleanupClientClosedV1)?
        {
            return Err(RootStopCleanupClientClosedV1);
        }
        Ok(RootStopCleanupClientCompletedBorrowV1 { owner: self })
    }
}

impl RootStopCleanupChildLoanV1<'_> {
    /// Lends the actual held Root effective deadline for the finite Host child.
    ///
    /// Source22 retains its separate original financial deadline. Its closed
    /// child binder uses this borrowed bound for Host1 and the second Host3,
    /// including the observation branch. Each actual native/send frontier must
    /// independently enforce that narrowed bound; this getter samples no clock.
    ///
    /// # Errors
    /// Refuses a finished or failed child or changed Source22/C native custody.
    pub fn effective_cutoff_data_v1(
        &self,
        source: &Source<'_, '_>,
        controller: &Journal,
    ) -> Result<u64, RootStopCleanupClientClosedV1> {
        if self.finished || self.guard.owner.first.is_some() {
            return Err(RootStopCleanupClientClosedV1);
        }
        self.guard
            .owner
            .require_source(source, controller)
            .map_err(|_| RootStopCleanupClientClosedV1)?;
        Ok(self
            .guard
            .owner
            .native
            .as_ref()
            .ok_or(RootStopCleanupClientClosedV1)?
            .cutoff)
    }

    /// Borrows only the actual normalized signed effect; observation returns None.
    ///
    /// # Errors
    /// Refuses changed Source22/C custody, a failed or finished child interval.
    pub fn effect_v1(
        &self,
        source: &Source<'_, '_>,
        controller: &Journal,
    ) -> Result<Option<&crate::PreparedAuthorityEffectV1>, RootStopCleanupClientClosedV1> {
        if self.finished || self.guard.owner.first.is_some() {
            return Err(RootStopCleanupClientClosedV1);
        }
        self.guard
            .owner
            .require_source(source, controller)
            .map_err(|_| RootStopCleanupClientClosedV1)?;
        let native = self
            .guard
            .owner
            .native
            .as_ref()
            .ok_or(RootStopCleanupClientClosedV1)?;
        if native.observed {
            return Ok(None);
        }
        positive(
            &native
                .signing
                .as_ref()
                .ok_or(RootStopCleanupClientClosedV1)?
                .effect,
        )
        .map(Some)
    }

    /// Drains the actual Root after even when the Host child refuses or unwinds.
    ///
    /// `body_succeeded` records only primary refusal; it cannot prove Host
    /// completion, which the final native Root reader independently authenticates.
    ///
    /// # Errors
    /// Refuses primary failure, repeated entry or an independent native after.
    pub fn finish_native_once_v1(
        &mut self,
        body_succeeded: bool,
    ) -> Result<(), RootStopCleanupClientClosedV1> {
        if self.finished {
            return Err(self.guard.owner.refuse_reentry());
        }
        self.finished = true;
        if !body_succeeded {
            self.guard
                .owner
                .repeated
                .get_or_insert(RootStopCleanupClientClosedV1);
            self.guard.owner.first.get_or_insert(First::External);
        }
        let _ = self.guard.owner.drain_owed(&self.guard.profile);
        if self.guard.owner.first.is_some() {
            return Err(RootStopCleanupClientClosedV1);
        }
        self.guard.owner.phase = 3;
        Ok(())
    }

    /// Borrows the actual retained Root cause without another observation.
    #[must_use]
    pub fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.guard.owner.failure_v1()
    }
}

impl Drop for RootStopCleanupChildLoanV1<'_> {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.finish_native_once_v1(false);
        }
    }
}

impl RootStopCleanupClientCompletedBorrowV1<'_> {
    /// Reports the actual completed Root decision's effect branch as comparison DATA.
    ///
    /// This discriminator comes from the retained strict initial Root reply,
    /// rather than comparing its decision digest with a later observation row.
    /// It creates no Host1 grant or permission to append Source completion.
    ///
    /// # Errors
    /// Refuses an incomplete or failed physical Root original.
    pub fn executed_cleanup_data_v1(&self) -> Result<bool, RootStopCleanupClientClosedV1> {
        Ok(!self.owner.require_completed()?.observed)
    }

    /// Rejoins the actual current fresh Source22 original and final native query.
    ///
    /// # Errors
    /// Refuses foreign, disposed, failed or changed native Source/C custody.
    pub fn require_same_source22_v1(
        &self,
        source: &Source<'_, '_>,
        controller: &Journal,
    ) -> Result<(), RootStopCleanupClientClosedV1> {
        self.owner
            .borrow_completed_once_v1(source, controller)
            .map(|_| ())
    }

    /// Returns the exact query commitment of this physically completed exchange.
    ///
    /// # Errors
    /// Refuses an incomplete or failed physical Root original.
    pub fn query_digest_v1(&self) -> Result<[u8; 32], RootStopCleanupClientClosedV1> {
        Ok(self.owner.require_completed()?.query_digest)
    }

    /// Returns the actual normalized effect or completed-observation commitment.
    ///
    /// # Errors
    /// Refuses an incomplete or failed physical Root original.
    pub fn decision_digest_v1(&self) -> Result<[u8; 32], RootStopCleanupClientClosedV1> {
        Ok(self.owner.require_completed()?.decision_digest)
    }

    /// Returns the canonical signed outcome commitment of the actual final Host3.
    ///
    /// # Errors
    /// Refuses an incomplete Root original or missing actual final Host3.
    pub fn final_host_outcome_digest_v1(&self) -> Result<[u8; 32], RootStopCleanupClientClosedV1> {
        Ok(self
            .owner
            .require_completed()?
            .final_host
            .ok_or(RootStopCleanupClientClosedV1)?
            .3)
    }

    /// Borrows the exact received permanent-F48 bytes after EOF and native posts.
    ///
    /// # Errors
    /// Refuses incomplete native completion or a changed fixed response extent.
    pub fn completion_bytes_v1(
        &self,
    ) -> Result<&[u8; ROOT_POLICY_POSITIVE_COMPLETION_BYTES_V2], RootStopCleanupClientClosedV1>
    {
        self.owner.require_completed()?.replies[2]
            .received
            .bytes()
            .try_into()
            .map_err(|_| RootStopCleanupClientClosedV1)
    }

    /// Returns the already verified unchanged authority wall bound as comparison DATA.
    ///
    /// # Errors
    /// Refuses an incomplete or failed physical Root original.
    pub fn verified_authority_expiry_data_v1(&self) -> Result<i64, RootStopCleanupClientClosedV1> {
        Ok(self.owner.require_completed()?.expiry)
    }
}
