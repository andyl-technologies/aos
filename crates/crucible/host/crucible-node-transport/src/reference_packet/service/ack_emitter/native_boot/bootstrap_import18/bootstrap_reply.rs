//! Constructs the original bootstrap-only reply inside the verified SDK loan.
//!
//! Each output survives refusal and remains charged to the original occurrence.
//! The sealed reply also retains its separately reserved canonical frame proposal;
//! encoding records no transfer and cannot complete a physical publication.
//! Construction reserves no outgoing SDK record and publishes no ACK. A signed
//! receipt is DATA; opaque Source funding and native permission remain separate.
//!
//! ```text
//! response.body = {status: "completed", operation_state: "completed",
//!                  result: BootstrapResult18, extensions: {}}
//! response.extensions = {bootstrap-ack-receipt18: BootstrapAckReceipt18}
//! ```

use super::bootstrap_operands::BootstrapAckOperands;
use super::bootstrap_proof::{self as proof, Attempt as Proof};
use super::*;
use crate::envelope::Envelope;
use crate::reference_packet::service::PacketNative5SourceLaunch;
use crate::reference_packet::service::complete_restore::PACKET_COMPLETE_RESTORE_ALGORITHM;
use crate::reference_packet::service::complete_restore::import18::bootstrap_ack::{
    NATIVE_IMPORT18_BOOTSTRAP_ACK_RECEIPT, NATIVE_IMPORT18_BOOTSTRAP_RESULT_SCHEMA,
    PacketNativeImport18BootstrapAckContext as Context,
    PacketNativeImport18BootstrapAckReceipt as Receipt, PacketNativeImport18BootstrapAckState,
    PacketNativeImport18BootstrapRequest as Request,
    PacketNativeImport18BootstrapResult as ReplyResult,
    native_import18_bootstrap_ack_assigned_response_digest,
    native_import18_bootstrap_ack_counter_scratch_data,
    native_import18_bootstrap_ack_projection_data,
};
use crate::reference_packet::service::complete_restore::import18::{
    OriginalImport18DecodedBodyLoans as BodyLoans,
    PacketNativeImport18PrivateBootWireData as BootData,
    PacketNativeImport18SelectedLaunchWireData,
};
use crucible_node_format::Bytes;
use std::rc::{Rc, Weak};

#[path = "bootstrap_reply/literal.rs"]
mod literal;
#[path = "bootstrap_reply/publication.rs"]
pub(super) mod publication;
#[path = "bootstrap_reply/response.rs"]
mod response;
#[path = "bootstrap_reply/storage.rs"]
mod storage;

/// Borrows every original predecessor and its independently verified proof.
#[derive(Clone, Copy)]
pub(in super::super) struct Inputs<'a> {
    /// Borrows the original raw, typed and SDK request owners.
    pub(in super::super) prior: proof::Inputs<'a>,
    /// Borrows retained verification without moving its context or key.
    pub(in super::super) proof: &'a Proof,
}

/// Names separately admitted outputs of the complete reply constructor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in super::super) enum Step {
    /// Retains the actual bootstrap-only result before correspondence checks.
    Result,
    /// Retains the complete response with the actual SDK sequence.
    Envelope,
    /// Retains the authoritative assigned-response digest.
    Assigned,
    /// Retains the distinct receipt before validation.
    Receipt,
    /// Inserts the sole receipt18 extension into the retained response.
    Seal,
    /// Retains the distinct closed-shape response journal before allocation.
    ReserveLiteral,
    /// Retains the actual sealed response serializer tree.
    SerializeLiteral,
    /// Retains the actual canonical count under negotiated framing.
    MeasureLiteral,
    /// Retains the original framed proposal with no physical transfer.
    EncodeLiteral,
}

/// Admits each output and observes its actual surviving allocation census.
pub(in super::super) trait Admission {
    /// Admits the complete stored row before any output allocation.
    ///
    /// Callback allocations and diagnostics need enclosing credit.
    ///
    /// # Errors
    /// Refuses missing original credit or incomplete actual-owner custody.
    fn construct_data(
        &self,
        inputs: Inputs<'_>,
        attempt: &Attempt,
        row: [usize; 3],
    ) -> Result<(), ProviderError>;

    /// Admits the next operation beside every retained original and output.
    ///
    /// # Errors
    /// Refuses unavailable credit or incomplete original correspondence.
    fn step_data(
        &self,
        inputs: Inputs<'_>,
        attempt: &Attempt,
        step: Step,
    ) -> Result<(), ProviderError>;

    /// Observes retained outputs after either outcome of the named operation.
    ///
    /// # Errors
    /// Refuses unavailable credit or incomplete surviving-state census.
    fn observe_data(
        &self,
        inputs: Inputs<'_>,
        attempt: &Attempt,
        step: Step,
        actual: usize,
    ) -> Result<(), ProviderError>;
}

/// Retains complete preparation and its separately admitted SDK publication.
pub(in super::super) struct Attempt {
    started: bool,
    complete: bool,
    failed: bool,
    cut: Option<OperationalDeadline>,
    launch: Option<Weak<PacketNativeImport18SelectedLaunchWireData>>,
    row: Option<[usize; 3]>,
    step: Option<Step>,
    result: Option<ReplyResult>,
    envelope: Option<Envelope>,
    assigned: Option<[u8; 32]>,
    receipt: Option<Receipt>,
    literal: literal::Literal,
    publication: publication::Publication,
}

impl Attempt {
    /// Initializes retained slots without allocating or inspecting input.
    pub(in super::super) fn empty_data() -> Self {
        Self {
            started: false,
            complete: false,
            failed: false,
            cut: None,
            launch: None,
            row: None,
            step: None,
            result: None,
            envelope: None,
            assigned: None,
            receipt: None,
            literal: literal::Literal::empty_data(),
            publication: publication::Publication::empty_data(),
        }
    }

    fn authenticate_alias(
        &self,
        original: &OriginalImport18RawBootstrap,
    ) -> Result<(), ProviderError> {
        if let Some(launch) = &self.launch {
            if !Weak::ptr_eq(
                launch,
                &Rc::downgrade(original.parsed.shared_launch_data()?),
            ) {
                return Err(refused());
            }
        }
        Ok(())
    }

    fn authenticate(
        &self,
        inputs: Inputs<'_>,
        operands: &BootstrapAckOperands<'_>,
    ) -> Result<(), ProviderError> {
        let original = inputs.prior.prior.original;
        self.authenticate_alias(original)?;
        if self.cut != Some(original.cut) || original.cut.is_expired() {
            return Err(refused());
        }
        original.authenticate_channel()?;
        operands.ensure_current_authority_data()
    }

    /// Counts all surviving output backing, including after refusal or expiry.
    ///
    /// # Errors
    /// Refuses another original association, unsupported metadata or overflow.
    pub(in super::super) fn retained_requested_bytes_data(
        &self,
        original: &OriginalImport18RawBootstrap,
    ) -> Result<usize, ProviderError> {
        self.authenticate_alias(original)?;
        storage::retained_data(self)
    }
}

impl OriginalImport18RawBootstrap {
    /// Constructs the first bootstrap reply once without reserving or publishing it.
    ///
    /// Both occurrences are spent before guards. Refusal fences the actual SDK
    /// guard and retains its accepted request and every constructed output.
    ///
    /// # Errors
    /// Refuses retry, incomplete predecessors, stale custody, short credit,
    /// admission, output correspondence, receipt construction or terminal guards.
    pub(in super::super) fn construct_bootstrap_reply_data(
        &mut self,
        normalizations: &super::bootstrap_normalizations::Attempt,
        literal: &super::bootstrap_literal::Attempt,
        parsed: &super::bootstrap_value::Attempt,
        codec: &super::bootstrap_codec::Attempt,
        correlation: &mut super::bootstrap_correlation::Attempt,
        proof: &Proof,
        attempt: &mut Attempt,
        admission: &dyn Admission,
    ) -> Result<(), ProviderError> {
        if self.bootstrap_reply_started || attempt.started {
            return Err(refused());
        }
        self.bootstrap_reply_started = true;
        attempt.started = true;
        let inputs = Inputs {
            prior: proof::Inputs {
                prior: super::bootstrap_correlation::Inputs {
                    original: self,
                    normalizations,
                    literal,
                    parsed,
                    codec,
                },
                correlation: correlation.view_data(),
            },
            proof,
        };
        let outcome = construct_current(inputs, attempt, admission);
        let terminal = self.authenticate_channel();
        if let Err(error) = outcome.and(terminal) {
            attempt.failed = true;
            correlation.refuse_data();
            let _ = self.hello_registrar.contain_admission_data();
            return Err(error);
        }
        attempt.complete = true;
        Ok(())
    }

    /// Verifies and constructs the original reply inside one complete SDK loan.
    ///
    /// All four once flags are spent before guards. Verification and reply keep
    /// separate admissions and surviving-output censuses. Neither attempt is
    /// completed until the shared aggregate has passed every original terminal
    /// guard. This transition reserves no outgoing response and publishes no ACK.
    ///
    /// # Errors
    /// Refuses retry, incomplete predecessors, stale custody, short credit,
    /// verification/reply admission, assignment, MAC or terminal guards.
    pub(in super::super) fn verify_and_construct_bootstrap_reply_data(
        &mut self,
        normalizations: &super::bootstrap_normalizations::Attempt,
        literal: &super::bootstrap_literal::Attempt,
        parsed: &super::bootstrap_value::Attempt,
        codec: &super::bootstrap_codec::Attempt,
        correlation: &mut super::bootstrap_correlation::Attempt,
        verified: &mut Proof,
        verification: &dyn proof::Admission,
        attempt: &mut Attempt,
        admission: &dyn Admission,
    ) -> Result<(), ProviderError> {
        if self.bootstrap_proof_started
            || self.bootstrap_reply_started
            || verified.started_data()
            || attempt.started
        {
            return Err(refused());
        }
        self.bootstrap_proof_started = true;
        self.bootstrap_reply_started = true;
        verified.start_data();
        attempt.started = true;
        let prior = proof::Inputs {
            prior: super::bootstrap_correlation::Inputs {
                original: self,
                normalizations,
                literal,
                parsed,
                codec,
            },
            correlation: correlation.view_data(),
        };
        let outcome = proof::verify_current_with_data(
            prior,
            verified,
            verification,
            |proof, context, envelope, request, guard, operands| {
                construct_under_verified_data(
                    Inputs { prior, proof },
                    attempt,
                    admission,
                    context,
                    envelope,
                    request,
                    guard,
                    operands,
                )
            },
        );
        let terminal = self.authenticate_channel();
        if let Err(error) = outcome.and(terminal) {
            verified.refuse_data();
            attempt.failed = true;
            correlation.refuse_data();
            let _ = self.hello_registrar.contain_admission_data();
            return Err(error);
        }
        verified.complete_data();
        attempt.complete = true;
        Ok(())
    }
}

fn construct_current(
    inputs: Inputs<'_>,
    attempt: &mut Attempt,
    admission: &dyn Admission,
) -> Result<(), ProviderError> {
    inputs.proof.with_verified_operands_data(
        inputs.prior,
        |context, envelope, request, guard, operands| {
            construct_under_verified_data(
                inputs, attempt, admission, context, envelope, request, guard, operands,
            )
        },
    )
}

// Both entry points call this only inside their complete actual correlation
// loan. The combined path retains the still-pending verified context until the
// outer original owner marks both attempts complete after all terminal guards.
fn construct_under_verified_data(
    inputs: Inputs<'_>,
    attempt: &mut Attempt,
    admission: &dyn Admission,
    context: &Context,
    envelope: &Envelope,
    request: &Request,
    guard: &crate::session::CorrelationGuard,
    operands: &BootstrapAckOperands<'_>,
) -> Result<(), ProviderError> {
    let original = inputs.prior.prior.original;
    attempt.cut = Some(original.cut);
    attempt.launch = Some(Rc::downgrade(original.parsed.shared_launch_data()?));

    attempt.authenticate(inputs, operands)?;
    original.admit_source_row(
        original
            .initial_construction
            .as_ref()
            .ok_or_else(refused)?
            .row,
    )?;
    // The same immutable decoded owners stay borrowed until the full
    // enclosing correlation/SDK loan has checked both aggregate outcomes.
    let bodies = original.typed_bodies_data()?;
    let [maximum_frame, maximum_nesting] = operands.current_framing_limits_data()?;
    if maximum_frame as u64 > bodies.launch.launch_data().limits.frame_bytes.get()
        || maximum_nesting as u64 > bodies.launch.launch_data().limits.nesting.get()
    {
        return Err(refused());
    }
    let row = construction_data(bodies.launch.launch_data(), original.bounds.requested_peak)?;
    attempt.row = Some(row);
    let retained = inputs
        .prior
        .prior
        .retained_data(row[0])?
        .checked_add(
            inputs
                .prior
                .correlation
                .retained_requested_bytes_data(original)?,
        )
        .ok_or_else(exhausted)?;
    let retained = retained
        .checked_add(inputs.proof.retained_requested_bytes_data(original)?)
        .ok_or_else(exhausted)?;
    original.admit_source_row([retained, row[1], row[2]])?;
    admission.construct_data(inputs, attempt, row)?;
    attempt.authenticate(inputs, operands)?;
    for step in [
        Step::Result,
        Step::Envelope,
        Step::Assigned,
        Step::Receipt,
        Step::Seal,
        Step::ReserveLiteral,
        Step::SerializeLiteral,
        Step::MeasureLiteral,
        Step::EncodeLiteral,
    ] {
        admission.step_data(inputs, attempt, step)?;
        attempt.authenticate(inputs, operands)?;
        attempt.step = Some(step);
        let outcome = construct_step(
            bodies.boot,
            maximum_frame,
            maximum_nesting,
            attempt,
            context,
            envelope,
            request,
            guard,
            step,
        );
        let terminal = attempt.authenticate(inputs, operands);
        let census = attempt
            .retained_requested_bytes_data(original)
            .and_then(|actual| {
                let observed = admission.observe_data(inputs, attempt, step, actual);
                let coverage = if actual <= attempt.row.ok_or_else(refused)?[0] {
                    Ok(())
                } else {
                    Err(exhausted())
                };
                observed?;
                coverage
            });
        let observed = attempt.authenticate(inputs, operands);
        outcome?;
        terminal?;
        census?;
        observed?;
    }
    Ok(())
}

fn construct_step(
    boot: &BootData,
    maximum_frame: usize,
    maximum_nesting: usize,
    attempt: &mut Attempt,
    context: &Context,
    envelope: &Envelope,
    request: &Request,
    guard: &crate::session::CorrelationGuard,
    step: Step,
) -> Result<(), ProviderError> {
    match step {
        Step::Result => {
            attempt.result = Some(ReplyResult {
                schema: NATIVE_IMPORT18_BOOTSTRAP_RESULT_SCHEMA.into(),
                state: PacketNativeImport18BootstrapAckState::BootstrapOnly,
                recipe_identity: Bytes::new(request.recipe_identity.as_slice().to_vec()),
                initial_funding: request.initial_funding,
            });
            attempt
                .result
                .as_ref()
                .ok_or_else(refused)?
                .authenticate_request_data(request)?;
        }
        Step::Envelope => {
            attempt.envelope = Some(response::build_data(
                envelope,
                guard,
                attempt.result.as_ref().ok_or_else(refused)?,
            )?);
            let reply = attempt.envelope.as_ref().ok_or_else(refused)?;
            reply.validate()?;
            envelope.matches_response(reply)?;
        }
        Step::Assigned => {
            attempt.assigned = Some(native_import18_bootstrap_ack_assigned_response_digest(
                envelope,
                attempt.envelope.as_ref().ok_or_else(refused)?,
                maximum_frame,
            )?);
        }
        Step::Receipt => {
            attempt.receipt = Some(
                boot.bootstrap_ack_receipt_data(context, &attempt.assigned.ok_or_else(refused)?)?,
            );
            attempt
                .receipt
                .as_ref()
                .ok_or_else(refused)?
                .validate_data()?;
        }
        Step::Seal => {
            let reply = attempt.envelope.as_mut().ok_or_else(refused)?;
            if !reply.extensions.is_empty() {
                return Err(refused());
            }
            let value = serde_json::to_value(attempt.receipt.as_ref().ok_or_else(refused)?)
                .map_err(crucible_node_format::ContractError::from)?;
            reply
                .extensions
                .insert(NATIVE_IMPORT18_BOOTSTRAP_ACK_RECEIPT.into(), value);
            reply.validate()?;
            envelope.matches_response(reply)?;
        }
        Step::ReserveLiteral => attempt
            .literal
            .reserve_data(storage::extent_data()?.maximum_canonical_encoded_bytes)?,
        Step::SerializeLiteral => attempt
            .literal
            .serialize_data(attempt.envelope.as_ref().ok_or_else(refused)?)?,
        Step::MeasureLiteral => attempt
            .literal
            .measure_data(maximum_frame, maximum_nesting)?,
        Step::EncodeLiteral => attempt
            .literal
            .encode_data(envelope.request_id.0.as_ref().ok_or_else(refused)?)?,
    }
    Ok(())
}

/// Quotes the complete reply constructor independently of announced funding.
///
/// # Errors
/// Refuses invalid framing, unsupported layouts, overflow or short restriction.
pub(in crate::reference_packet::service) fn construction_data(
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
) -> Result<[usize; 3], ProviderError> {
    if launch.limits.frame_bytes.get() == 0
        || launch.limits.frame_bytes.get() > crate::transport::MAX_FRAME_BYTES as u64
    {
        return Err(refused());
    }
    let mut row = storage::construction_data(launch, maximum)?;
    row[2] = row[2]
        .checked_add(counter_scratch_data()?)
        .ok_or_else(exhausted)?;
    if row
        .into_iter()
        .try_fold(0usize, usize::checked_add)
        .is_none_or(|sum| sum > maximum)
    {
        return Err(exhausted());
    }
    Ok(row)
}

/// Names constructor, observation and current verified-loan controls.
///
/// # Errors
/// Refuses checked layout accumulation overflow.
pub(in crate::reference_packet::service) fn counter_scratch_data() -> Result<usize, ProviderError> {
    let fields: [usize; 27] = [
        storage::counter_scratch_data(),
        BootstrapAckOperands::framing_counter_scratch_data(),
        combined_counter_scratch_data(),
        size_of::<Inputs<'static>>() * 6,
        size_of::<&Attempt>(),
        size_of::<&mut Attempt>(),
        size_of::<&dyn Admission>(),
        size_of::<&BootstrapAckOperands<'static>>(),
        size_of::<&Context>(),
        size_of::<&Envelope>() * 2,
        size_of::<&Request>(),
        size_of::<BodyLoans<'static>>(),
        size_of::<Result<BodyLoans<'static>, ProviderError>>(),
        size_of::<&BootData>(),
        size_of::<Result<usize, std::num::TryFromIntError>>(),
        size_of::<&crate::session::CorrelationGuard>(),
        size_of::<[Step; 9]>(),
        size_of::<std::array::IntoIter<Step, 9>>(),
        size_of::<Step>() * 4,
        size_of::<[usize; 3]>() * 3,
        size_of::<Result<[usize; 3], ProviderError>>(),
        size_of::<Result<(), ProviderError>>() * 9,
        size_of::<Weak<PacketNativeImport18SelectedLaunchWireData>>(),
        size_of::<usize>() * 7,
        size_of::<Option<usize>>(),
        size_of::<[usize; 27]>(),
        size_of::<std::array::IntoIter<usize, 27>>(),
    ];
    fields.into_iter().try_fold(
        Proof::verified_loan_counter_scratch_data::<()>()?,
        |sum, field| sum.checked_add(field).ok_or_else(exhausted),
    )
}

// The fused dispatcher adds only fixed views beside the independently priced
// sequential proof and reply work; no bank or diagnostic is cloned between them.
fn combined_counter_scratch_data() -> usize {
    size_of::<Inputs<'static>>() * 2
        + size_of::<proof::Inputs<'static>>() * 2
        + size_of::<&mut OriginalImport18RawBootstrap>()
        + size_of::<&mut Proof>()
        + size_of::<&Proof>()
        + size_of::<&mut Attempt>()
        + size_of::<&dyn proof::Admission>()
        + size_of::<&dyn Admission>()
        + size_of::<&Context>()
        + size_of::<&Envelope>()
        + size_of::<&Request>()
        + size_of::<&crate::session::CorrelationGuard>()
        + size_of::<&BootstrapAckOperands<'static>>()
        + size_of::<Result<(), ProviderError>>() * 5
}

fn refused() -> ProviderError {
    ProviderError::Correlation("original bootstrap reply refused")
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("original bootstrap reply construction DATA")
}

#[cfg(test)]
#[path = "bootstrap_reply/tests.rs"]
pub(super) mod tests;
