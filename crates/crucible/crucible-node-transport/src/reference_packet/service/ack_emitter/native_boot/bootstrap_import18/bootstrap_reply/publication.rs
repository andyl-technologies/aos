//! Publishes the one prepared original bootstrap response under complete custody.
//!
//! Preparation, transport publication and actual
//! native phase permission remain distinct. Only a genuine enclosing Source
//! producer can supply the admissions used here.

use super::super::bootstrap_correlation as correlation;
use super::*;
use crate::session::CorrelationGuard;

/// Names actual SDK ownership before reservation, during writing and after move.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Received,
    Writing,
    Confirmed,
}

/// Names separately admitted irreversible transport operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in super::super) enum Step {
    /// Reserves the exact response in the original SDK.
    Reserve,
    /// Writes the retained frame on the original physical stream.
    Write,
    /// Moves actual SDK records only after the full physical write.
    Confirm,
}

/// Retains publication state and actual records moved from SDK confirmation.
pub(in super::super) struct Publication {
    started: bool,
    complete: bool,
    failed: bool,
    cut: Option<OperationalDeadline>,
    launch: Option<Weak<PacketNativeImport18SelectedLaunchWireData>>,
    row: Option<[usize; 3]>,
    phase: Option<Phase>,
    step: Option<Step>,
    confirmed_request: Option<Envelope>,
    confirmed_response: Option<Envelope>,
    failure: Option<ProviderError>,
}

impl Publication {
    /// Initializes empty publication slots without allocation.
    pub(in super::super) fn empty_data() -> Self {
        Self {
            started: false,
            complete: false,
            failed: false,
            cut: None,
            launch: None,
            row: None,
            phase: None,
            step: None,
            confirmed_request: None,
            confirmed_response: None,
            failure: None,
        }
    }
}

/// Borrows original predecessor custody without borrowing the mutable SDK owner.
#[derive(Clone, Copy)]
pub(in super::super) struct Inputs<'a> {
    prior: correlation::Inputs<'a>,
    proof: &'a Proof,
    pending: bool,
}

/// Borrows the actual surviving response and SDK for one admission/census.
#[derive(Clone, Copy)]
pub(in super::super) struct Current<'a> {
    inputs: Inputs<'a>,
    reply: &'a Attempt,
    guard: &'a CorrelationGuard,
}

/// Admits effects and observes every actual original/SDK/publication owner.
pub(in super::super) trait Admission {
    /// Admits the complete publication row before SDK mutation or I/O.
    ///
    /// # Errors
    /// Refuses missing original credit or incomplete surviving custody.
    fn construct_data(&self, current: Current<'_>, row: [usize; 3]) -> Result<(), ProviderError>;

    /// Admits one irreversible effect beside every actual predecessor.
    ///
    /// # Errors
    /// Refuses unavailable credit or changed original correspondence.
    fn step_data(&self, current: Current<'_>, step: Step) -> Result<(), ProviderError>;

    /// Observes every surviving owner after either outcome.
    ///
    /// # Errors
    /// Refuses incomplete census or insufficient actual credit.
    fn observe_data(
        &self,
        current: Current<'_>,
        step: Step,
        actual: usize,
    ) -> Result<(), ProviderError>;
}

/// Borrows the independently admitted verification, preparation and publication.
///
/// Each operation keeps its own defining callback and complete retained census.
#[derive(Clone, Copy)]
pub(in super::super::super) struct Admissions<'a> {
    /// Admits proof verification and every surviving verifier output.
    pub(in super::super::super) verification: &'a dyn proof::Admission,
    /// Admits reply preparation and every constructed response prefix.
    pub(in super::super::super) preparation: &'a dyn super::Admission,
    /// Admits SDK mutation, physical publication and terminal record custody.
    pub(in super::super::super) publication: &'a dyn Admission,
}

impl Attempt {
    fn current_publication_data<'a>(
        &'a self,
        inputs: Inputs<'a>,
        guard: &'a CorrelationGuard,
    ) -> Current<'a> {
        Current {
            inputs,
            reply: self,
            guard,
        }
    }

    fn guard_publication_data(
        &self,
        inputs: Inputs<'_>,
        guard: &CorrelationGuard,
        original: &Envelope,
        operands: &BootstrapAckOperands<'_>,
    ) -> Result<(), ProviderError> {
        let root = inputs.prior.original;
        self.authenticate_alias(root)?;
        let publication = &self.publication;
        if (!self.complete && !inputs.pending)
            || self.failed
            || self.step != Some(super::Step::EncodeLiteral)
            || !publication.started
            || publication.failed
            || publication.failure.is_some()
            || publication.cut != Some(root.cut)
            || root.cut.is_expired()
        {
            return Err(refused());
        }
        let launch = publication.launch.as_ref().ok_or_else(refused)?;
        if !Weak::ptr_eq(launch, &Rc::downgrade(root.parsed.shared_launch_data()?)) {
            return Err(refused());
        }
        root.authenticate_channel()?;
        operands.ensure_current_authority_data()?;
        let (context, context_digest) =
            inputs
                .proof
                .constructed_publication_context_data(root, operands, inputs.pending)?;
        let receipt = self.receipt.as_ref().ok_or_else(refused)?;
        let result = self.result.as_ref().ok_or_else(refused)?;
        if receipt.context_digest.as_slice() != context_digest
            || receipt.assigned_response.as_slice() != self.assigned.as_ref().ok_or_else(refused)?
            || result.recipe_identity != context.recipe_identity
            || result.initial_funding != context.initial_funding
            || receipt.state != PacketNativeImport18BootstrapAckState::BootstrapOnly
        {
            return Err(refused());
        }
        let response = self.envelope.as_ref().ok_or_else(refused)?;
        original.matches_response(response)?;
        match publication.phase.ok_or_else(refused)? {
            Phase::Received => {
                if guard.original_bootstrap_response_sequence_data(original)? != response.sequence {
                    return Err(refused());
                }
            }
            Phase::Writing => guard.original_bootstrap_writing_data(original, response)?,
            Phase::Confirmed => {
                self.literal.authenticate_written_data()?;
                let request = publication.confirmed_request.as_ref().ok_or_else(refused)?;
                let sent = publication
                    .confirmed_response
                    .as_ref()
                    .ok_or_else(refused)?;
                if request != original || sent != response {
                    return Err(refused());
                }
                guard.original_bootstrap_confirmed_data(request, sent)?;
            }
        }
        operands.ensure_current_authority_data()
    }

    fn publish_current_data(
        &mut self,
        inputs: Inputs<'_>,
        guard: &mut CorrelationGuard,
        original: &Envelope,
        operands: &BootstrapAckOperands<'_>,
        admission: &dyn Admission,
    ) -> Result<(), ProviderError> {
        let root = inputs.prior.original;
        self.publication.cut = Some(root.cut);
        self.publication.launch = Some(Rc::downgrade(root.parsed.shared_launch_data()?));
        self.publication.phase = Some(Phase::Received);
        self.guard_publication_data(inputs, guard, original, operands)?;
        // The complete Source/native initial formula already includes this
        // nested publication's lifetime maximum inside the actual Reply row.
        let row = construction_data(
            root.typed_bodies_data()?.launch.launch_data(),
            root.bounds.requested_peak,
        )?;
        self.publication.row = Some(row);
        root.admit_source_row(root.initial_construction.as_ref().ok_or_else(refused)?.row)?;
        let actual = self
            .current_publication_data(inputs, guard)
            .retained_data()?;
        let empty_reply = self.retained_requested_bytes_data(root)?;
        let proposed = actual
            .checked_sub(empty_reply)
            .and_then(|prior| prior.checked_add(row[0]))
            .ok_or_else(exhausted)?;
        root.admit_source_row([proposed, row[1], row[2]])?;
        admission.construct_data(self.current_publication_data(inputs, guard), row)?;
        self.guard_publication_data(inputs, guard, original, operands)?;
        for step in [Step::Reserve, Step::Write, Step::Confirm] {
            admission.step_data(self.current_publication_data(inputs, guard), step)?;
            self.guard_publication_data(inputs, guard, original, operands)?;
            self.publication.step = Some(step);
            let outcome = self.publish_step_data(inputs, guard, original, operands, step);
            let terminal = self.guard_publication_data(inputs, guard, original, operands);
            // The observation must run after either outcome and after releasing
            // the mutable stream loan, including complete/partial write refusal.
            let census = self
                .current_publication_data(inputs, guard)
                .retained_data()
                .and_then(|actual| {
                    let observation = admission.observe_data(
                        self.current_publication_data(inputs, guard),
                        step,
                        actual,
                    );
                    let coverage = root.admit_source_row([actual, row[1], row[2]]);
                    observation?;
                    coverage
                });
            let observed = self.guard_publication_data(inputs, guard, original, operands);
            outcome?;
            terminal?;
            census?;
            observed?;
        }
        Ok(())
    }

    fn publish_step_data(
        &mut self,
        inputs: Inputs<'_>,
        guard: &mut CorrelationGuard,
        original: &Envelope,
        operands: &BootstrapAckOperands<'_>,
        step: Step,
    ) -> Result<(), ProviderError> {
        let root = inputs.prior.original;
        let response = self.envelope.as_ref().ok_or_else(refused)?;
        match step {
            Step::Reserve => {
                guard.register_outgoing(response.clone())?;
                self.publication.phase = Some(Phase::Writing);
            }
            Step::Write => {
                let mut holder = root.hello_exchange.borrow_mut_data()?;
                root.hello_publication.with_completed_stream_data(
                    holder.as_mut().ok_or_else(refused)?,
                    root.cut,
                    |stream| {
                        self.literal.write_prepared_data(
                            stream,
                            &mut self.publication.failure,
                            || {
                                root.authenticate_channel()?;
                                operands.ensure_current_authority_data()?;
                                guard.original_bootstrap_writing_data(original, response)
                            },
                        )
                    },
                )?;
            }
            Step::Confirm => {
                self.literal.authenticate_written_data()?;
                guard.original_bootstrap_confirm_into_data(
                    original,
                    response,
                    &mut self.publication.confirmed_request,
                    &mut self.publication.confirmed_response,
                )?;
                self.publication.phase = Some(Phase::Confirmed);
            }
        }
        Ok(())
    }
}

impl OriginalImport18RawBootstrap {
    /// Publishes the prepared original bootstrap reply once under genuine credit.
    ///
    /// Both occurrence flags are spent before guards. Transport confirmation
    /// retains the actual moved SDK records and grants no native phase or Ready.
    ///
    /// # Errors
    /// Refuses retry, foreign/incomplete preparation, short credit, SDK state,
    /// partial/failed I/O, admission or any terminal original guard.
    pub(in super::super::super) fn publish_bootstrap_reply_data(
        &mut self,
        predecessors: correlation::Predecessors<'_>,
        correlation: &mut correlation::Attempt,
        proof: &Proof,
        reply: &mut Attempt,
        admission: &dyn Admission,
    ) -> Result<(), ProviderError> {
        if self.bootstrap_publication_started || reply.publication.started {
            return Err(refused());
        }
        self.bootstrap_publication_started = true;
        reply.publication.started = true;
        let prior = correlation::Inputs {
            original: self,
            normalizations: predecessors.normalizations,
            literal: predecessors.literal,
            parsed: predecessors.parsed,
            codec: predecessors.codec,
        };
        let inputs = Inputs {
            prior,
            proof,
            pending: false,
        };
        let outcome = correlation.with_publication_context_data(
            prior,
            |_header, guard, original, _request, _proof, operands, _digests| {
                reply.publish_current_data(inputs, guard, original, operands, admission)
            },
        );
        let terminal = self.authenticate_channel();
        if let Err(error) = outcome.and(terminal) {
            reply.publication.failed = true;
            correlation.refuse_data();
            let _ = self.hello_registrar.contain_admission_data();
            return Err(error);
        }
        reply.publication.complete = true;
        Ok(())
    }
}

impl Current<'_> {
    /// Counts every surviving original owner and the actual current SDK state.
    ///
    /// # Errors
    /// Refuses foreign associations, unsupported metadata or checked overflow.
    fn retained_data(self) -> Result<usize, ProviderError> {
        let root = self.inputs.prior.original;
        let correlation = correlation::publication::retained_borrowed_data(self.guard)?;
        let proof = self.inputs.proof.retained_requested_bytes_data(root)?;
        let reply = self.reply.retained_requested_bytes_data(root)?;
        self.inputs
            .prior
            .retained_data(correlation)?
            .checked_add(proof)
            .and_then(|sum| sum.checked_add(reply))
            .ok_or_else(exhausted)
    }
}

#[path = "publication/storage.rs"]
mod storage;

pub(super) use storage::{backing_construction_data, retained_backing_data};

#[cfg(test)]
#[path = "publication/tests.rs"]
pub(in super::super) mod tests;

impl OriginalImport18RawBootstrap {
    /// Verifies, prepares and publishes the original reply in one custody scope.
    ///
    /// All six occurrences are spent before guards. No completion escapes until
    /// the complete original Codec/Source/Host/SDK terminal checks succeed.
    ///
    /// # Errors
    /// Refuses retry, incomplete predecessors, stale custody, credit/admission,
    /// proof/preparation, partial I/O, SDK settlement or any terminal guard.
    pub(in super::super::super) fn verify_prepare_and_publish_bootstrap_reply_data(
        &mut self,
        predecessors: correlation::Predecessors<'_>,
        correlation: &mut correlation::Attempt,
        verified: &mut Proof,
        reply: &mut Attempt,
        admissions: Admissions<'_>,
    ) -> Result<(), ProviderError> {
        if self.bootstrap_proof_started
            || self.bootstrap_reply_started
            || self.bootstrap_publication_started
            || verified.started_data()
            || reply.started
            || reply.publication.started
        {
            return Err(refused());
        }
        self.bootstrap_proof_started = true;
        self.bootstrap_reply_started = true;
        self.bootstrap_publication_started = true;
        verified.start_data();
        reply.started = true;
        reply.publication.started = true;
        let prior = correlation::Inputs {
            original: self,
            normalizations: predecessors.normalizations,
            literal: predecessors.literal,
            parsed: predecessors.parsed,
            codec: predecessors.codec,
        };
        let outcome = correlation.with_publication_context_data(
            prior,
            |header, guard, envelope, request, proof, operands, digests| {
                // This immutable view ends before the actual SDK is reserved.
                let inputs = proof::Inputs {
                    prior,
                    correlation: header.with_guard_data(guard),
                };
                let received = proof::Received {
                    guard,
                    envelope,
                    request,
                    proof,
                    operands,
                    digests,
                };
                proof::verify_under_received_data(
                    inputs,
                    verified,
                    admissions.verification,
                    &received,
                    |proof, context, envelope, request, guard, operands| {
                        let verified = super::Verified {
                            context,
                            envelope,
                            request,
                            guard,
                            operands,
                        };
                        super::construct_under_verified_data(
                            super::Inputs {
                                prior: inputs,
                                proof,
                            },
                            reply,
                            admissions.preparation,
                            &verified,
                        )
                    },
                )?;
                reply.publish_current_data(
                    Inputs {
                        prior,
                        proof: verified,
                        pending: true,
                    },
                    guard,
                    envelope,
                    operands,
                    admissions.publication,
                )
            },
        );
        let terminal = self.authenticate_channel();
        if let Err(error) = outcome.and(terminal) {
            verified.refuse_data();
            reply.failed = true;
            reply.publication.failed = true;
            correlation.refuse_data();
            let _ = self.hello_registrar.contain_admission_data();
            return Err(error);
        }
        verified.complete_data();
        reply.complete = true;
        reply.publication.complete = true;
        Ok(())
    }
}
