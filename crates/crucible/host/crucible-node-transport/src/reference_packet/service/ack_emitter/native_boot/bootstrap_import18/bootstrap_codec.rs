//! Retains the original bootstrap Envelope, request and proof as unassigned DATA.
//!
//! Exact closed preflight precedes borrowed-Value decoding. Original raw/strict
//! owners remain live; each typed output is stored before validation and whole
//! census. No Session request, Source grant, MAC acceptance, ACK or model follows.

use super::bootstrap_literal::Attempt as Literal;
use super::bootstrap_normalizations::Attempt as Normalizations;
use super::bootstrap_operands::BootstrapAckOperands;
use super::bootstrap_value::Attempt as Parsed;
use super::*;
use crate::envelope::Envelope;
use crate::reference_packet::service::PacketNative5SourceLaunch;
use crate::reference_packet::service::complete_restore::import18::bootstrap_ack::{
    PacketNativeImport18BootstrapAckProof, PacketNativeImport18BootstrapRequest,
};
use serde_json::Value;
use std::rc::Rc;

#[path = "bootstrap_codec/attempt.rs"]
mod attempt;
#[path = "bootstrap_codec/prewalk.rs"]
mod prewalk;
#[path = "bootstrap_codec/storage.rs"]
mod storage;
pub(super) use attempt::observe_envelope_data;
pub(in super::super) use attempt::{Attempt, Step};
pub(super) use storage::envelope_text_data;

/// Borrows the four actual predecessors without granting decoding or funding.
#[derive(Clone, Copy)]
pub(in super::super) struct Inputs<'a> {
    /// Borrows the original private receiver and its current SDK custody.
    pub(in super::super) original: &'a OriginalImport18RawBootstrap,
    /// Borrows the five completed normalization outputs.
    pub(in super::super) normalizations: &'a Normalizations,
    /// Borrows the same retained public frame and failed read prefixes.
    pub(in super::super) literal: &'a Literal,
    /// Borrows the strict Value owner decoded from that frame.
    pub(in super::super) parsed: &'a Parsed,
}

/// Admits complete typed decoding and observes every surviving prefix.
pub(in super::super) trait Admission {
    /// Admits the stored closed codec row before any typed allocation.
    ///
    /// Callback allocations and errors require independent enclosing funding.
    ///
    /// # Errors
    /// Refuses missing original credit or incomplete whole-owner custody.
    fn construct_data(
        &self,
        inputs: &Inputs<'_>,
        attempt: &Attempt,
        row: [usize; 3],
    ) -> Result<(), ProviderError>;

    /// Observes actual retained outputs after either outcome of each decoder.
    ///
    /// A missing step identifies closed-preflight refusal before typed decoding.
    ///
    /// # Errors
    /// Refuses incomplete actual-owner observation or unavailable credit.
    fn observe_data(
        &self,
        inputs: &Inputs<'_>,
        attempt: &Attempt,
        step: Option<Step>,
        actual: usize,
    ) -> Result<(), ProviderError>;
}

impl OriginalImport18RawBootstrap {
    /// Decodes the three original bootstrap DTOs once without SDK assignment.
    ///
    /// The actual borrowed SDK stays inside one full original Host/literal/Value
    /// loan. Live authority checks separate admissions and decoder outcomes;
    /// every surviving output is observed before either outcome propagates.
    ///
    /// # Errors
    /// Refuses retry, incomplete/stale originals, short credit, closed preflight,
    /// typed decoding, original correspondence, admission or terminal guards.
    pub(in super::super) fn decode_bootstrap_codec_data(
        &mut self,
        normalizations: &Normalizations,
        literal: &Literal,
        parsed: &Parsed,
        attempt: &mut Attempt,
        admission: &dyn Admission,
    ) -> Result<(), ProviderError> {
        if self.bootstrap_codec_started || attempt.started {
            return Err(refused());
        }
        self.bootstrap_codec_started = true;
        attempt.started = true;
        let outcome = self.decode_current_bootstrap_codec(
            normalizations,
            literal,
            parsed,
            attempt,
            admission,
        );
        let terminal = self.authenticate_channel();
        if let Err(error) = outcome.and(terminal) {
            attempt.failed = true;
            let _ = self.hello_registrar.contain_admission_data();
            return Err(error);
        }
        attempt.complete = true;
        Ok(())
    }

    fn decode_current_bootstrap_codec(
        &self,
        normalizations: &Normalizations,
        literal: &Literal,
        parsed: &Parsed,
        attempt: &mut Attempt,
        admission: &dyn Admission,
    ) -> Result<(), ProviderError> {
        attempt.cut = Some(self.cut);
        attempt.launch = Some(Rc::downgrade(self.parsed.shared_launch_data()?));
        let inputs = Inputs {
            original: self,
            normalizations,
            literal,
            parsed,
        };
        parsed.with_value_and_operands_data(self, normalizations, literal, |value, operands, _| {
            attempt.guard(self, operands)?;
            self.admit_source_row(self.initial_construction.as_ref().ok_or_else(refused)?.row)?;
            let row = construction_data(
                self.typed_bodies_data()?.launch.launch_data(),
                self.bounds.requested_peak,
            )?;
            attempt.row = Some(row);
            let retained = self
                .retained_requested_bytes()?
                .checked_add(normalizations.retained_requested_bytes_data(self)?)
                .ok_or_else(exhausted)?;
            let retained = retained
                .checked_add(literal.retained_requested_bytes_data(self)?)
                .ok_or_else(exhausted)?;
            let retained = retained
                .checked_add(parsed.retained_requested_bytes_data(self)?)
                .ok_or_else(exhausted)?;
            let retained = retained.checked_add(row[0]).ok_or_else(exhausted)?;
            self.admit_source_row([retained, row[1], row[2]])?;
            admission.construct_data(&inputs, attempt, row)?;
            attempt.guard(self, operands)?;

            let closed = match prewalk::inspect_data(value) {
                Ok(closed) => closed,
                Err(error) => {
                    return observe_step(&inputs, attempt, admission, operands, None, Err(error));
                }
            };
            for step in [Step::Envelope, Step::Request, Step::Proof] {
                let outcome = attempt.construct_step(step, self, operands, value, &closed);
                observe_step(&inputs, attempt, admission, operands, Some(step), outcome)?;
            }
            Ok(())
        })
    }
}

fn observe_step(
    inputs: &Inputs<'_>,
    attempt: &Attempt,
    admission: &dyn Admission,
    operands: &BootstrapAckOperands<'_>,
    step: Option<Step>,
    outcome: Result<(), ProviderError>,
) -> Result<(), ProviderError> {
    let terminal = attempt.guard(inputs.original, operands);
    let census = attempt
        .retained_requested_bytes_data(inputs.original)
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
    let observed = attempt.guard(inputs.original, operands);
    outcome?;
    terminal?;
    census?;
    observed
}

impl Attempt {
    /// Quotes nested original loans and each concrete Copy-result wrapper.
    ///
    /// # Errors
    /// Refuses checked counter-layout accumulation overflow.
    pub(in super::super) fn request_loan_counter_scratch_data<R: Copy>()
    -> Result<usize, ProviderError> {
        [
            size_of::<&Self>(),
            size_of::<&OriginalImport18RawBootstrap>(),
            size_of::<&Normalizations>(),
            size_of::<&Literal>(),
            size_of::<&Parsed>(),
            size_of::<&BootstrapAckOperands<'static>>(),
            size_of::<super::bootstrap_normalizations::Digests>() * 2,
            size_of::<(
                &Envelope,
                &PacketNativeImport18BootstrapRequest,
                &PacketNativeImport18BootstrapAckProof,
            )>(),
            size_of::<
                Result<
                    (
                        &Envelope,
                        &PacketNativeImport18BootstrapRequest,
                        &PacketNativeImport18BootstrapAckProof,
                    ),
                    ProviderError,
                >,
            >(),
            size_of::<R>() * 3,
            size_of::<Result<R, ProviderError>>() * 3,
            size_of::<Result<(), ProviderError>>() * 2,
        ]
        .into_iter()
        .try_fold(
            Parsed::value_loan_counter_scratch_data::<R>()?,
            |sum, field| sum.checked_add(field).ok_or_else(exhausted),
        )
    }

    /// Lends completed unassigned DTOs inside their actual original SDK loan.
    ///
    /// Inspection and its concrete Copy result require independent admission.
    /// Parsed proofs remain unauthenticated DATA until their distinct verifier.
    ///
    /// # Errors
    /// Refuses incomplete/refused DTOs, stale originals, callback or terminal guards.
    pub(in super::super) fn with_request_data<R: Copy>(
        &self,
        original: &OriginalImport18RawBootstrap,
        normalizations: &Normalizations,
        literal: &Literal,
        parsed: &Parsed,
        inspect: impl FnOnce(
            &Envelope,
            &PacketNativeImport18BootstrapRequest,
            &PacketNativeImport18BootstrapAckProof,
        ) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        self.with_request_and_operands_data(
            original,
            normalizations,
            literal,
            parsed,
            |envelope, request, proof, _, _| inspect(envelope, request, proof),
        )
    }

    /// Lends completed typed DATA with the same original borrowed live SDK.
    ///
    /// Callback allocation and concrete Copy results require separate credit.
    ///
    /// # Errors
    /// Refuses incomplete DTOs, stale original custody/SDK or either outcome.
    pub(in super::super) fn with_request_and_operands_data<R: Copy>(
        &self,
        original: &OriginalImport18RawBootstrap,
        normalizations: &Normalizations,
        literal: &Literal,
        parsed: &Parsed,
        inspect: impl FnOnce(
            &Envelope,
            &PacketNativeImport18BootstrapRequest,
            &PacketNativeImport18BootstrapAckProof,
            &BootstrapAckOperands<'_>,
            super::bootstrap_normalizations::Digests,
        ) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        parsed.with_value_and_operands_data(
            original,
            normalizations,
            literal,
            |_, operands, digests| {
                self.guard(original, operands)?;
                let (envelope, request, proof) = self.data()?;
                let outcome = inspect(envelope, request, proof, operands, digests);
                let terminal = self
                    .guard(original, operands)
                    .and_then(|()| self.data().map(|_| ()));
                let result = outcome?;
                terminal?;
                Ok(result)
            },
        )
    }
}

/// Quotes the complete closed typed decoder under negotiated original framing.
///
/// The retained raw bank, strict Value, normalized hashes and original root have
/// separate terms in the independently calculated initial construction schedule.
///
/// # Errors
/// Refuses invalid framing, checked layout overflow or a short restriction.
pub(in crate::reference_packet::service) fn construction_data(
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
) -> Result<[usize; 3], ProviderError> {
    if launch.limits.frame_bytes.get() == 0
        || launch.limits.frame_bytes.get() > crate::transport::MAX_FRAME_BYTES as u64
    {
        return Err(refused());
    }
    let mut row = storage::construction_data(maximum)?;
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

/// Names the actual preflight, decoder, observation and original-loan controls.
///
/// # Errors
/// Refuses checked counter-layout accumulation overflow.
pub(in crate::reference_packet::service) fn counter_scratch_data() -> Result<usize, ProviderError> {
    let fields: [usize; 28] = [
        // The local view survives its closure, step-observer and admission borrows.
        size_of::<Inputs<'static>>() + size_of::<&Inputs<'static>>() * 3,
        prewalk::counter_scratch_data(),
        storage::counter_scratch_data(),
        size_of::<&Envelope>(),
        size_of::<&mut crate::retained_metadata::MetadataObserver>(),
        size_of::<Result<(), ProviderError>>(),
        size_of::<&OriginalImport18RawBootstrap>(),
        size_of::<&mut OriginalImport18RawBootstrap>(),
        size_of::<&Normalizations>(),
        size_of::<&Literal>(),
        size_of::<&Parsed>(),
        size_of::<&Attempt>(),
        size_of::<&mut Attempt>(),
        size_of::<&dyn Admission>(),
        size_of::<&BootstrapAckOperands<'static>>(),
        size_of::<super::bootstrap_normalizations::Digests>() * 2,
        size_of::<[usize; 3]>() * 2,
        size_of::<Result<[usize; 3], ProviderError>>(),
        size_of::<[Step; 3]>(),
        size_of::<std::array::IntoIter<Step, 3>>(),
        size_of::<[usize; 28]>(),
        size_of::<std::array::IntoIter<usize, 28>>(),
        size_of::<Option<Step>>(),
        size_of::<Step>(),
        size_of::<Result<(), ProviderError>>() * 6,
        size_of::<(
            &Envelope,
            &PacketNativeImport18BootstrapRequest,
            &PacketNativeImport18BootstrapAckProof,
        )>(),
        size_of::<usize>() * 6,
        size_of::<Option<usize>>(),
    ];
    fields.into_iter().try_fold(
        Attempt::request_loan_counter_scratch_data::<()>()?,
        |sum, field| sum.checked_add(field).ok_or_else(exhausted),
    )
}

#[cfg(test)]
#[path = "bootstrap_codec/tests.rs"]
pub(super) mod tests;
