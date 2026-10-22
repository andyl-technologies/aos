//! Verifies the original bootstrap proof under the complete current SDK loan.
//!
//! Context construction binds the actual normalization hashes, literal Hello
//! pair and correlated Envelope. Retained outputs survive every refusal. Even a
//! valid MAC supplies no Source occurrence, opaque Initial, ACK or native model.

use super::bootstrap_correlation::{self as correlation, Attempt as Correlation};
use super::bootstrap_normalizations::Digests;
use super::bootstrap_operands::BootstrapAckOperands;
use super::*;
use crate::envelope::Envelope;
use crate::reference_packet::service::PacketNative5SourceLaunch;
use crate::reference_packet::service::complete_restore::PACKET_COMPLETE_RESTORE_ALGORITHM;
use crate::reference_packet::service::complete_restore::import18::PacketNativeImport18SelectedLaunchWireData;
use crate::reference_packet::service::complete_restore::import18::bootstrap_ack::{
    NATIVE_IMPORT18_BOOTSTRAP_ACK_CONTEXT, PacketNativeImport18BootstrapAckContext as Context,
    PacketNativeImport18BootstrapAckProof as Proof,
    PacketNativeImport18BootstrapRequest as Request,
    native_import18_bootstrap_ack_assigned_request_digest,
    native_import18_bootstrap_ack_context_digest_data,
};
use crate::reference_packet::service::complete_restore::import18::{
    OriginalImport18DecodedBodyLoans as BodyLoans,
    PacketNativeImport18PrivateBootWireData as BootData,
};
use crucible_node_format::Bytes;
use std::rc::{Rc, Weak};

#[path = "bootstrap_proof/storage.rs"]
mod storage;

/// Borrows every actual predecessor, including the reserved SDK request.
#[derive(Clone, Copy)]
pub(in super::super) struct Inputs<'a> {
    /// Borrows all five original raw, normalized and typed owners.
    pub(in super::super) prior: correlation::Inputs<'a>,
    /// Borrows the actual current correlation owner without cloning a record.
    pub(in super::super) correlation: correlation::View<'a>,
}

/// Names separately admitted proof operations and their surviving outputs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in super::super) enum Step {
    /// Hashes the original assignment, excluding only its proof18 extension.
    Assigned,
    /// Retains the complete independently derived context before validation.
    Context,
    /// Retains the computed complete context digest before MAC verification.
    ContextDigest,
    /// Verifies the distinct bootstrap MAC using the original borrowed key.
    Verify,
}

/// Admits construction and each actual operation while observing all owners.
pub(in super::super) trait Admission {
    /// Admits the stored complete row before hashing or context allocation.
    ///
    /// Callback allocations and returned diagnostics require enclosing credit.
    ///
    /// # Errors
    /// Refuses unavailable credit or incomplete original-owner correspondence.
    fn construct_data(
        &self,
        inputs: Inputs<'_>,
        attempt: &Attempt,
        row: [usize; 3],
    ) -> Result<(), ProviderError>;

    /// Admits one operation while its previous outputs remain retained.
    ///
    /// # Errors
    /// Refuses unavailable credit or incomplete surviving custody.
    fn step_data(
        &self,
        inputs: Inputs<'_>,
        attempt: &Attempt,
        step: Step,
    ) -> Result<(), ProviderError>;

    /// Observes surviving outputs after either outcome of the named operation.
    ///
    /// # Errors
    /// Refuses incomplete actual census or missing original credit.
    fn observe_data(
        &self,
        inputs: Inputs<'_>,
        attempt: &Attempt,
        step: Step,
        actual: usize,
    ) -> Result<(), ProviderError>;
}

/// Retains independently derived proof outputs without issuing bootstrap credit.
pub(in super::super) struct Attempt {
    started: bool,
    complete: bool,
    failed: bool,
    cut: Option<OperationalDeadline>,
    launch: Option<Weak<PacketNativeImport18SelectedLaunchWireData>>,
    row: Option<[usize; 3]>,
    step: Option<Step>,
    assigned: Option<[u8; 32]>,
    context: Option<Context>,
    digest: Option<[u8; 32]>,
    verified: bool,
}

impl Attempt {
    /// Creates empty retained slots without allocating or inspecting input.
    pub(in super::super) fn empty_data() -> Self {
        Self {
            started: false,
            complete: false,
            failed: false,
            cut: None,
            launch: None,
            row: None,
            step: None,
            assigned: None,
            context: None,
            digest: None,
            verified: false,
        }
    }

    /// Reports whether this external occurrence has already been spent.
    pub(super) fn started_data(&self) -> bool {
        self.started
    }

    /// Spends an empty external occurrence before the enclosing original guards.
    pub(super) fn start_data(&mut self) {
        self.started = true;
    }

    /// Preserves outputs while closing an aggregate verification/reply attempt.
    pub(super) fn refuse_data(&mut self) {
        self.failed = true;
    }

    /// Records completion only after the original aggregate terminal guards.
    pub(super) fn complete_data(&mut self) {
        self.complete = true;
    }

    fn authenticate_alias(
        &self,
        original: &OriginalImport18RawBootstrap,
    ) -> Result<(), ProviderError> {
        if let Some(launch) = &self.launch
            && !Weak::ptr_eq(
                launch,
                &Rc::downgrade(original.parsed.shared_launch_data()?),
            )
        {
            return Err(refused());
        }
        Ok(())
    }

    fn authenticate(
        &self,
        inputs: Inputs<'_>,
        operands: &BootstrapAckOperands<'_>,
    ) -> Result<(), ProviderError> {
        let original = inputs.prior.original;
        self.authenticate_alias(original)?;
        if self.cut != Some(original.cut) || original.cut.is_expired() {
            return Err(refused());
        }
        original.authenticate_channel()?;
        operands.ensure_current_authority_data()
    }

    /// Counts the actual retained context, including after expiry or refusal.
    ///
    /// # Errors
    /// Refuses another original association or checked backing overflow.
    pub(in super::super) fn retained_requested_bytes_data(
        &self,
        original: &OriginalImport18RawBootstrap,
    ) -> Result<usize, ProviderError> {
        self.authenticate_alias(original)?;
        let mut retained = size_of::<Self>();
        if let Some(context) = &self.context {
            retained = retained
                .checked_add(context.schema.capacity())
                .and_then(|sum| sum.checked_add(context.algorithm.capacity()))
                .ok_or_else(exhausted)?;
            for bytes in [
                &context.source_birth,
                &context.kernel_binding,
                &context.policy_binding,
                &context.host_registration,
                &context.native_registration,
                &context.hello_request,
                &context.hello_response,
                &context.assigned_request,
                &context.recipe_identity,
            ] {
                retained = retained
                    .checked_add(bytes.allocation_capacity())
                    .ok_or_else(exhausted)?;
            }
        }
        Ok(retained)
    }

    /// Lends completed context DATA inside every original current correlation guard.
    ///
    /// Inspection and its concrete Copy result need separately admitted credit.
    /// This loan grants no ACK, Source allowance or native phase permission.
    ///
    /// # Errors
    /// Refuses incomplete verification, stale originals, callback or terminal guards.
    pub(in super::super) fn with_verified_context_data<R: Copy>(
        &self,
        inputs: Inputs<'_>,
        inspect: impl FnOnce(&Context) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        self.with_verified_operands_data(inputs, |context, _, _, _, _| inspect(context))
    }

    /// Lends verified context DATA and the same actual current request operands.
    ///
    /// Inspection and its Copy result require separately admitted credit. The
    /// original SDK record remains reserved before and after either callback
    /// outcome. This loan does not reserve or publish an outgoing response.
    ///
    /// # Errors
    /// Refuses incomplete verification, stale original custody or either outcome.
    pub(super) fn with_verified_operands_data<R: Copy>(
        &self,
        inputs: Inputs<'_>,
        inspect: impl FnOnce(
            &Context,
            &Envelope,
            &Request,
            &crate::session::CorrelationGuard,
            &BootstrapAckOperands<'_>,
        ) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        if !self.complete || self.failed || !self.verified || self.step != Some(Step::Verify) {
            return Err(refused());
        }
        inputs.correlation.with_received_context_data(
            inputs.prior,
            |guard, original, request, _, operands, _| {
                self.authenticate(inputs, operands)?;
                let outcome = inspect(
                    self.context.as_ref().ok_or_else(refused)?,
                    original,
                    request,
                    guard,
                    operands,
                );
                let terminal = self.authenticate(inputs, operands);
                let result = outcome?;
                terminal?;
                Ok(result)
            },
        )
    }

    /// Quotes every nested current loan and concrete Copy-result control.
    ///
    /// # Errors
    /// Refuses checked layout accumulation overflow.
    pub(in super::super) fn verified_loan_counter_scratch_data<R: Copy>()
    -> Result<usize, ProviderError> {
        [
            size_of::<Inputs<'static>>() * 3,
            size_of::<&Self>(),
            size_of::<&Context>(),
            size_of::<&Envelope>(),
            size_of::<&Request>(),
            size_of::<&crate::session::CorrelationGuard>(),
            size_of::<&BootstrapAckOperands<'static>>(),
            size_of::<R>() * 3,
            size_of::<Result<R, ProviderError>>() * 3,
            size_of::<Result<(), ProviderError>>() * 2,
            size_of::<[usize; 12]>(),
            size_of::<std::array::IntoIter<usize, 12>>(),
        ]
        .into_iter()
        .try_fold(
            Correlation::received_loan_counter_scratch_data::<R>()?,
            |sum, field| sum.checked_add(field).ok_or_else(exhausted),
        )
    }
}

impl OriginalImport18RawBootstrap {
    /// Verifies the original reserved bootstrap proof once without granting a phase.
    ///
    /// Both attempts are spent before guards. Any refusal fences the actual SDK
    /// correlation while retaining its accepted request and every proof output.
    ///
    /// # Errors
    /// Refuses retry, incomplete predecessors, stale custody, short credit,
    /// admission, assignment/context correspondence, MAC or terminal guards.
    pub(in super::super) fn verify_bootstrap_proof_data(
        &mut self,
        normalizations: &super::bootstrap_normalizations::Attempt,
        literal: &super::bootstrap_literal::Attempt,
        parsed: &super::bootstrap_value::Attempt,
        codec: &super::bootstrap_codec::Attempt,
        correlation: &mut Correlation,
        attempt: &mut Attempt,
        admission: &dyn Admission,
    ) -> Result<(), ProviderError> {
        if self.bootstrap_proof_started || attempt.started {
            return Err(refused());
        }
        self.bootstrap_proof_started = true;
        attempt.started = true;
        let inputs = Inputs {
            prior: correlation::Inputs {
                original: self,
                normalizations,
                literal,
                parsed,
                codec,
            },
            correlation: correlation.view_data(),
        };
        let outcome = verify_current(inputs, attempt, admission);
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
}

fn verify_current(
    inputs: Inputs<'_>,
    attempt: &mut Attempt,
    admission: &dyn Admission,
) -> Result<(), ProviderError> {
    verify_current_with_data(inputs, attempt, admission, |_, _, _, _, _, _| Ok(()))
}

/// Lends constructed verification only inside the same aggregate correlation loan.
///
/// Completion is recorded by the outer original owner after every terminal guard.
/// No callback result creates Source funding, an opaque recipe or phase permission.
///
/// # Errors
/// Preserves verification, original custody, callback and terminal refusals.
pub(super) fn verify_current_with_data<R: Copy>(
    inputs: Inputs<'_>,
    attempt: &mut Attempt,
    admission: &dyn Admission,
    inspect: impl FnOnce(
        &Attempt,
        &Context,
        &Envelope,
        &Request,
        &crate::session::CorrelationGuard,
        &BootstrapAckOperands<'_>,
    ) -> Result<R, ProviderError>,
) -> Result<R, ProviderError> {
    inputs.correlation.with_received_context_data(
        inputs.prior,
        |guard, envelope, request, proof, operands, digests| {
            verify_under_received_data(
                inputs, attempt, admission, guard, envelope, request, proof, operands, digests,
                inspect,
            )
        },
    )
}

/// Verifies inside an already held complete original received-request scope.
///
/// # Errors
/// Preserves all proof, admission, actual-owner census and terminal refusals.
pub(super) fn verify_under_received_data<R: Copy>(
    inputs: Inputs<'_>,
    attempt: &mut Attempt,
    admission: &dyn Admission,
    guard: &crate::session::CorrelationGuard,
    envelope: &Envelope,
    request: &Request,
    proof: &Proof,
    operands: &BootstrapAckOperands<'_>,
    digests: Digests,
    inspect: impl FnOnce(
        &Attempt,
        &Context,
        &Envelope,
        &Request,
        &crate::session::CorrelationGuard,
        &BootstrapAckOperands<'_>,
    ) -> Result<R, ProviderError>,
) -> Result<R, ProviderError> {
    let original = inputs.prior.original;
    attempt.cut = Some(original.cut);
    attempt.launch = Some(Rc::downgrade(original.parsed.shared_launch_data()?));
    guard.original_bootstrap_response_sequence_data(envelope)?;
    attempt.authenticate(inputs, operands)?;
    original.admit_source_row(
        original
            .initial_construction
            .as_ref()
            .ok_or_else(refused)?
            .row,
    )?;
    // The complete immutable decoded owners remain inside this actual
    // correlation loan until its terminal guards. Borrow them once for
    // all four steps instead of re-opening the raw-body loan per field.
    let bodies = original.typed_bodies_data()?;
    let maximum_frame = usize::try_from(bodies.launch.launch_data().limits.frame_bytes.get())
        .map_err(|_| exhausted())?;
    let row = construction_data(bodies.launch.launch_data(), original.bounds.requested_peak)?;
    attempt.row = Some(row);
    let retained = inputs
        .prior
        .retained_data(row[0])?
        .checked_add(inputs.correlation.retained_requested_bytes_data(original)?)
        .ok_or_else(exhausted)?;
    original.admit_source_row([retained, row[1], row[2]])?;
    admission.construct_data(inputs, attempt, row)?;
    attempt.authenticate(inputs, operands)?;

    for step in [
        Step::Assigned,
        Step::Context,
        Step::ContextDigest,
        Step::Verify,
    ] {
        admission.step_data(inputs, attempt, step)?;
        attempt.authenticate(inputs, operands)?;
        attempt.step = Some(step);
        let outcome = construct_step(
            inputs,
            attempt,
            operands,
            envelope,
            request,
            proof,
            digests,
            bodies.boot,
            maximum_frame,
            step,
        );
        observe_step(inputs, attempt, admission, operands, step, outcome)?;
    }
    inspect(
        attempt,
        attempt.context.as_ref().ok_or_else(refused)?,
        envelope,
        request,
        guard,
        operands,
    )
}

fn construct_step(
    inputs: Inputs<'_>,
    attempt: &mut Attempt,
    operands: &BootstrapAckOperands<'_>,
    envelope: &Envelope,
    request: &Request,
    proof: &Proof,
    digests: Digests,
    boot: &BootData,
    maximum_frame: usize,
    step: Step,
) -> Result<(), ProviderError> {
    let original = inputs.prior.original;
    match step {
        Step::Assigned => {
            attempt.assigned = Some(native_import18_bootstrap_ack_assigned_request_digest(
                envelope,
                maximum_frame,
            )?);
        }
        Step::Context => {
            let hello = original.published_hello_frame_digests_under_operands_data(operands)?;
            attempt.context = Some(Context {
                schema: NATIVE_IMPORT18_BOOTSTRAP_ACK_CONTEXT.into(),
                algorithm: PACKET_COMPLETE_RESTORE_ALGORITHM.into(),
                source_birth: Bytes::new(digests.birth.to_vec()),
                kernel_binding: Bytes::new(digests.kernel.to_vec()),
                policy_binding: Bytes::new(digests.policy.to_vec()),
                host_registration: Bytes::new(digests.host_registration.to_vec()),
                native_registration: Bytes::new(digests.native_registration.to_vec()),
                hello_request: Bytes::new(hello.request_frame_digest.to_vec()),
                hello_response: Bytes::new(hello.response_frame_digest.to_vec()),
                assigned_request: Bytes::new(attempt.assigned.ok_or_else(refused)?.to_vec()),
                recipe_identity: Bytes::new(request.recipe_identity.as_slice().to_vec()),
                initial_funding: request.initial_funding,
            });
            attempt
                .context
                .as_ref()
                .ok_or_else(refused)?
                .validate_data()?;
        }
        Step::ContextDigest => {
            attempt.digest = Some(native_import18_bootstrap_ack_context_digest_data(
                attempt.context.as_ref().ok_or_else(refused)?,
            )?);
        }
        Step::Verify => {
            boot.verify_bootstrap_ack_proof_data(
                attempt.context.as_ref().ok_or_else(refused)?,
                proof,
            )?;
            attempt.verified = true;
        }
    }
    Ok(())
}

fn observe_step(
    inputs: Inputs<'_>,
    attempt: &Attempt,
    admission: &dyn Admission,
    operands: &BootstrapAckOperands<'_>,
    step: Step,
    outcome: Result<(), ProviderError>,
) -> Result<(), ProviderError> {
    let terminal = attempt.authenticate(inputs, operands);
    let census = attempt
        .retained_requested_bytes_data(inputs.prior.original)
        .and_then(|actual| {
            let observation = admission.observe_data(inputs, attempt, step, actual);
            let coverage = if actual <= attempt.row.ok_or_else(refused)?[0] {
                Ok(())
            } else {
                Err(exhausted())
            };
            observation?;
            coverage
        });
    let observed = attempt.authenticate(inputs, operands);
    outcome?;
    terminal?;
    census?;
    observed
}

/// Quotes complete original proof construction without issuing funding.
///
/// # Errors
/// Refuses invalid launch geometry, overflow or a short independent restriction.
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

/// Names actual constructors, observations and concrete current-loan controls.
///
/// # Errors
/// Refuses checked layout accumulation overflow.
pub(in crate::reference_packet::service) fn counter_scratch_data() -> Result<usize, ProviderError> {
    let fields = [
        storage::counter_scratch_data(),
        received_core_counter_scratch_data::<()>()?,
        size_of::<Inputs<'static>>() * 6,
        size_of::<&Attempt>() * 2,
        size_of::<&mut Attempt>(),
        size_of::<&dyn Admission>(),
        size_of::<&BootstrapAckOperands<'static>>(),
        size_of::<Digests>() * 3,
        size_of::<&Envelope>(),
        size_of::<&Request>(),
        size_of::<&Proof>(),
        size_of::<[Step; 4]>(),
        size_of::<std::array::IntoIter<Step, 4>>(),
        size_of::<Step>() * 4,
        size_of::<[usize; 3]>() * 3,
        size_of::<Result<[usize; 3], ProviderError>>(),
        size_of::<Result<(), ProviderError>>() * 11,
        size_of::<Weak<PacketNativeImport18SelectedLaunchWireData>>(),
        size_of::<usize>() * 6,
        size_of::<Option<usize>>(),
        size_of::<BodyLoans<'static>>(),
        size_of::<Result<BodyLoans<'static>, ProviderError>>(),
        size_of::<&BootData>(),
        size_of::<Result<usize, std::num::TryFromIntError>>(),
        size_of::<[usize; 26]>(),
        size_of::<std::array::IntoIter<usize, 26>>(),
    ];
    fields.into_iter().try_fold(
        Attempt::verified_loan_counter_scratch_data::<()>()?,
        |sum, field| sum.checked_add(field).ok_or_else(exhausted),
    )
}

// The thin core remains inside the original received-request scope. Its fixed
// borrowed arguments and concrete Copy result coexist with that outer loan.
fn received_core_counter_scratch_data<R: Copy>() -> Result<usize, ProviderError> {
    let terms = [
        crate::session::CorrelationGuard::original_bootstrap_response_sequence_counter_scratch_data(
        ),
        size_of::<Inputs<'static>>(),
        size_of::<&mut Attempt>(),
        size_of::<&dyn Admission>(),
        size_of::<&crate::session::CorrelationGuard>(),
        size_of::<&Envelope>(),
        size_of::<&Request>(),
        size_of::<&Proof>(),
        size_of::<&BootstrapAckOperands<'static>>(),
        size_of::<Digests>(),
        size_of::<R>() * 2,
        size_of::<Result<R, ProviderError>>() * 2,
    ];
    let controls = std::mem::size_of_val(&terms) + std::mem::size_of_val(&terms.into_iter());
    terms.into_iter().try_fold(controls, |sum, term| {
        sum.checked_add(term).ok_or_else(exhausted)
    })
}

fn refused() -> ProviderError {
    ProviderError::Correlation("original bootstrap proof refused")
}
fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("original bootstrap proof construction DATA")
}

#[cfg(test)]
#[path = "bootstrap_proof/tests.rs"]
pub(super) mod tests;

#[path = "bootstrap_proof/publication.rs"]
mod publication;
