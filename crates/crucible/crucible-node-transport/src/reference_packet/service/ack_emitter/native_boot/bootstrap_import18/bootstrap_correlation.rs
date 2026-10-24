//! Owns actual bootstrap request correlation under its original SDK and channel.
//!
//! A fresh CorrelationGuard borrows construction parameters from the actual
//! admitted SDK. Its first receive retains the actual decoded Envelope before
//! proof verification. This transport record grants no ACK, model or readiness.

use super::bootstrap_codec::Attempt as Codec;
use super::bootstrap_literal::Attempt as Literal;
use super::bootstrap_normalizations::Attempt as Normalizations;
use super::bootstrap_operands::BootstrapAckOperands;
use super::bootstrap_value::Attempt as Parsed;
use super::*;
use crate::envelope::Envelope;
use crate::reference_packet::service::PacketNative5SourceLaunch;
use crate::reference_packet::service::complete_restore::import18::PacketNativeImport18SelectedLaunchWireData;
use crate::reference_packet::service::complete_restore::import18::bootstrap_ack::{
    PacketNativeImport18BootstrapAckProof, PacketNativeImport18BootstrapRequest,
};
use crate::retained_metadata::{MetadataObserver, requested_metadata_backing_storage_data};
use crate::session::CorrelationGuard;
use std::rc::{Rc, Weak};

// The pinned SDK accessors lend the existing incoming/pending map views.
type RequestValues<'a> =
    std::collections::btree_map::Values<'a, crucible_node_format::Id, Envelope>;

#[path = "bootstrap_correlation/storage.rs"]
mod storage;

/// Borrows external Bootstrap predecessors independently of the mutable receiver.
///
/// This view carries the same four owners into verification and publication.
/// It supplies no currentness, admission, SDK settlement or phase permission.
#[derive(Clone, Copy)]
pub(in super::super) struct Predecessors<'a> {
    /// Borrows the completed original normalization outputs.
    pub(in super::super) normalizations: &'a Normalizations,
    /// Borrows the retained post-Hello frame and read prefixes.
    pub(in super::super) literal: &'a Literal,
    /// Borrows the strict tree decoded from that frame.
    pub(in super::super) parsed: &'a Parsed,
    /// Borrows the corresponding unassigned typed request and proof.
    pub(in super::super) codec: &'a Codec,
}

/// Borrows all actual predecessors without moving or substituting any owner.
#[derive(Clone, Copy)]
pub(in super::super) struct Inputs<'a> {
    /// Borrows the complete original inherited-channel owner.
    pub(in super::super) original: &'a OriginalImport18RawBootstrap,
    /// Borrows the completed five original normalization hashes.
    pub(in super::super) normalizations: &'a Normalizations,
    /// Borrows the actual post-Hello literal bank.
    pub(in super::super) literal: &'a Literal,
    /// Borrows the strict tree decoded from that same bank.
    pub(in super::super) parsed: &'a Parsed,
    /// Borrows the completed unassigned typed prefix.
    pub(in super::super) codec: &'a Codec,
}

impl Inputs<'_> {
    /// Counts every original and external predecessor with the proposed owner.
    ///
    /// # Errors
    /// Refuses foreign associations, incomplete census or checked overflow.
    pub(super) fn retained_data(&self, current: usize) -> Result<usize, ProviderError> {
        let Self {
            original,
            normalizations,
            literal,
            parsed,
            codec,
        } = self;
        [
            original.retained_requested_bytes()?,
            normalizations.retained_requested_bytes_data(original)?,
            literal.retained_requested_bytes_data(original)?,
            parsed.retained_requested_bytes_data(original)?,
            codec.retained_requested_bytes_data(original)?,
            current,
        ]
        .into_iter()
        .try_fold(0usize, |sum, bytes| {
            sum.checked_add(bytes).ok_or_else(exhausted)
        })
    }
}

/// Names actual construction and first-receive boundaries, without phase credit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in super::super) enum Step {
    /// Constructs an empty guard from the same admitted SDK parameters.
    Construct,
    /// Reserves the actual decoded first post-Hello request in that guard.
    Receive,
}

/// Admits SDK correlation work while observing every actual predecessor.
pub(in super::super) trait Admission {
    /// Admits the stored complete row before cloning any negotiated parameter.
    ///
    /// Callback allocations and diagnostics require independent enclosing credit.
    ///
    /// # Errors
    /// Refuses short credit or incomplete actual-owner correspondence.
    fn construct_data(
        &self,
        inputs: Inputs<'_>,
        attempt: &Attempt,
        row: [usize; 3],
    ) -> Result<(), ProviderError>;

    /// Admits the original request's SDK reservation after guard construction.
    ///
    /// # Errors
    /// Refuses missing credit or an incomplete empty-guard census.
    fn receive_data(&self, inputs: Inputs<'_>, attempt: &Attempt) -> Result<(), ProviderError>;

    /// Observes retained SDK state after either outcome at the named boundary.
    ///
    /// # Errors
    /// Refuses missing credit or incomplete surviving custody.
    fn observe_data(
        &self,
        inputs: Inputs<'_>,
        attempt: &Attempt,
        step: Step,
        actual: usize,
    ) -> Result<(), ProviderError>;
}

/// Retains the actual correlation guard and every accepted request on refusal.
pub(in super::super) struct Attempt {
    started: bool,
    complete: bool,
    failed: bool,
    cut: Option<OperationalDeadline>,
    launch: Option<Weak<PacketNativeImport18SelectedLaunchWireData>>,
    row: Option<[usize; 3]>,
    step: Option<Step>,
    guard: Option<CorrelationGuard>,
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
            guard: None,
        }
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
        self.authenticate_alias(inputs.original)?;
        if self.cut != Some(inputs.original.cut) || inputs.original.cut.is_expired() {
            return Err(refused());
        }
        inputs.original.authenticate_channel()?;
        operands.ensure_current_authority_data()
    }

    /// Counts actual guard backing even after expiry, fencing or terminal refusal.
    ///
    /// # Errors
    /// Refuses foreign association, metadata limits or checked storage overflow.
    pub(in super::super) fn retained_requested_bytes_data(
        &self,
        original: &OriginalImport18RawBootstrap,
    ) -> Result<usize, ProviderError> {
        self.authenticate_alias(original)?;
        self.requested_storage_data()
    }

    /// Counts actual SDK backing without accepting an original association.
    ///
    /// # Errors
    /// Refuses metadata limits, unsupported tree layouts or checked overflow.
    fn requested_storage_data(&self) -> Result<usize, ProviderError> {
        let mut observer = MetadataObserver::new();
        if let Some(guard) = &self.guard {
            guard.observe_owned_metadata(&mut observer)?;
        }
        size_of::<Self>()
            .checked_add(requested_metadata_backing_storage_data(&observer.finish())?)
            .ok_or_else(exhausted)
    }

    /// Fences a failed composite consumer while preserving every accepted record.
    pub(super) fn refuse_data(&mut self) {
        self.failed = true;
        if let Some(guard) = &mut self.guard {
            guard.fence();
        }
    }

    fn authenticate_received(&self, envelope: &Envelope) -> Result<(), ProviderError> {
        let guard = self.guard.as_ref().ok_or_else(refused)?;
        let mut incoming = guard.incoming_requests();
        if incoming.next() != Some(envelope)
            || incoming.next().is_some()
            || guard.pending_requests().next().is_some()
        {
            return Err(refused());
        }
        Ok(())
    }

    /// Quotes nested original loans and each concrete Copy-result wrapper.
    ///
    /// # Errors
    /// Refuses checked counter-layout accumulation overflow.
    pub(in super::super) fn received_loan_counter_scratch_data<R: Copy>()
    -> Result<usize, ProviderError> {
        let fields: [usize; 17] = [
            view::counter_scratch_data(),
            size_of::<Inputs<'static>>() * 3,
            size_of::<&Self>(),
            size_of::<&CorrelationGuard>(),
            size_of::<RequestValues<'static>>() * 3,
            size_of::<Option<&Envelope>>() * 4,
            size_of::<Result<&Envelope, ProviderError>>(),
            size_of::<&Envelope>(),
            size_of::<&PacketNativeImport18BootstrapRequest>(),
            size_of::<&PacketNativeImport18BootstrapAckProof>(),
            size_of::<super::bootstrap_normalizations::Digests>() * 2,
            size_of::<&BootstrapAckOperands<'static>>(),
            size_of::<Result<(), ProviderError>>() * 2,
            size_of::<R>() * 3,
            size_of::<Result<R, ProviderError>>() * 3,
            size_of::<[usize; 17]>(),
            size_of::<std::array::IntoIter<usize, 17>>(),
        ];
        fields.into_iter().try_fold(
            Codec::request_loan_counter_scratch_data::<R>()?,
            |sum, field| sum.checked_add(field).ok_or_else(exhausted),
        )
    }

    /// Lends the actual reserved request inside all original SDK/Host guards.
    ///
    /// Inspection and concrete Copy results require independently admitted credit.
    ///
    /// # Errors
    /// Refuses incomplete/fenced correlation, stale originals or either outcome.
    pub(in super::super) fn with_received_data<R: Copy>(
        &self,
        inputs: Inputs<'_>,
        inspect: impl FnOnce(&CorrelationGuard, &Envelope) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        self.with_received_context_data(inputs, |guard, envelope, _, _, _, _| {
            inspect(guard, envelope)
        })
    }

    /// Lends the actual reserved request and all original proof operands together.
    ///
    /// The five normalization hashes travel through the same nested literal,
    /// strict and typed loan. No independent SDK or normalization loan opens.
    /// Callback allocations and Copy results need separately admitted credit.
    ///
    /// # Errors
    /// Refuses incomplete/fenced correlation, stale originals or either outcome.
    pub(super) fn with_received_context_data<R: Copy>(
        &self,
        inputs: Inputs<'_>,
        inspect: impl FnOnce(
            &CorrelationGuard,
            &Envelope,
            &PacketNativeImport18BootstrapRequest,
            &PacketNativeImport18BootstrapAckProof,
            &BootstrapAckOperands<'_>,
            super::bootstrap_normalizations::Digests,
        ) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        if !self.complete || self.failed || self.step != Some(Step::Receive) {
            return Err(refused());
        }
        inputs.codec.with_request_and_operands_data(
            inputs.original,
            inputs.normalizations,
            inputs.literal,
            inputs.parsed,
            |envelope, request, proof, operands, digests| {
                self.authenticate(inputs, operands)?;
                self.authenticate_received(envelope)?;
                let guard = self.guard.as_ref().ok_or_else(refused)?;
                let received = guard.incoming_requests().next().ok_or_else(refused)?;
                let outcome = inspect(guard, received, request, proof, operands, digests);
                let terminal = self
                    .authenticate(inputs, operands)
                    .and_then(|()| self.authenticate_received(envelope));
                let result = outcome?;
                terminal?;
                Ok(result)
            },
        )
    }
}

impl OriginalImport18RawBootstrap {
    /// Reserves the actual first bootstrap request once in current SDK correlation.
    ///
    /// Both occurrences are spent before guards. Every surviving SDK state is
    /// observed on either outcome, and a failed attempt fences without releasing
    /// its records. Proof verification remains a subsequent admission.
    ///
    /// # Errors
    /// Refuses retry, incomplete predecessors, stale custody, insufficient credit,
    /// SDK reservation, admission or any terminal original guard.
    pub(in super::super) fn retain_bootstrap_correlation_data(
        &mut self,
        normalizations: &Normalizations,
        literal: &Literal,
        parsed: &Parsed,
        codec: &Codec,
        attempt: &mut Attempt,
        admission: &dyn Admission,
    ) -> Result<(), ProviderError> {
        if self.bootstrap_correlation_started || attempt.started {
            return Err(refused());
        }
        self.bootstrap_correlation_started = true;
        attempt.started = true;
        let inputs = Inputs {
            original: self,
            normalizations,
            literal,
            parsed,
            codec,
        };
        let outcome = construct_current(inputs, attempt, admission);
        let terminal = self.authenticate_channel();
        if let Err(error) = outcome.and(terminal) {
            attempt.failed = true;
            if let Some(guard) = &mut attempt.guard {
                guard.fence();
            }
            let _ = self.hello_registrar.contain_admission_data();
            return Err(error);
        }
        attempt.complete = true;
        Ok(())
    }
}

fn construct_current(
    inputs: Inputs<'_>,
    attempt: &mut Attempt,
    admission: &dyn Admission,
) -> Result<(), ProviderError> {
    attempt.cut = Some(inputs.original.cut);
    attempt.launch = Some(Rc::downgrade(inputs.original.parsed.shared_launch_data()?));
    inputs.codec.with_request_and_operands_data(
        inputs.original,
        inputs.normalizations,
        inputs.literal,
        inputs.parsed,
        |envelope, _, _, operands, _| {
            attempt.authenticate(inputs, operands)?;
            let original = inputs.original;
            original.admit_source_row(
                original
                    .initial_construction
                    .as_ref()
                    .ok_or_else(refused)?
                    .row,
            )?;
            let row = construction_data(
                original.typed_bodies_data()?.launch.launch_data(),
                original.bounds.requested_peak,
            )?;
            attempt.row = Some(row);
            original.admit_source_row([inputs.retained_data(row[0])?, row[1], row[2]])?;
            admission.construct_data(inputs, attempt, row)?;
            attempt.authenticate(inputs, operands)?;

            attempt.step = Some(Step::Construct);
            let outcome = operands.retain_bootstrap_correlation_into_data(&mut attempt.guard);
            observe_step(
                inputs,
                attempt,
                admission,
                operands,
                Step::Construct,
                outcome,
            )?;
            admission.receive_data(inputs, attempt)?;
            attempt.authenticate(inputs, operands)?;

            attempt.step = Some(Step::Receive);
            let outcome = attempt
                .guard
                .as_mut()
                .ok_or_else(refused)?
                .receive(envelope);
            observe_step(inputs, attempt, admission, operands, Step::Receive, outcome)?;
            attempt.authenticate_received(envelope)
        },
    )
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
    let observed = attempt.authenticate(inputs, operands);
    outcome?;
    terminal?;
    census?;
    observed
}

/// Quotes cloned negotiated parameters and one actual original request record.
///
/// This DATA quote cannot construct SDK state, credit, a native token or a model.
///
/// # Errors
/// Refuses invalid current launch geometry, overflow or a short restriction.
pub(in crate::reference_packet::service) fn construction_data(
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
) -> Result<[usize; 3], ProviderError> {
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

/// Quotes the defining constructor, census, callbacks and concrete unit loan.
///
/// # Errors
/// Refuses checked counter-layout accumulation overflow.
pub(in crate::reference_packet::service) fn counter_scratch_data() -> Result<usize, ProviderError> {
    let fields: [usize; 20] = [
        storage::counter_scratch_data(),
        size_of::<Inputs<'static>>() * 5,
        size_of::<&Attempt>(),
        size_of::<&mut Attempt>(),
        size_of::<&dyn Admission>(),
        size_of::<&BootstrapAckOperands<'static>>(),
        size_of::<&Envelope>(),
        size_of::<Option<Step>>(),
        size_of::<Step>() * 2,
        size_of::<[usize; 3]>() * 2,
        size_of::<Result<[usize; 3], ProviderError>>(),
        size_of::<[usize; 6]>(),
        size_of::<std::array::IntoIter<usize, 6>>(),
        // The pinned incoming/pending accessors return these actual map views.
        size_of::<RequestValues<'static>>() * 2,
        size_of::<Result<(), ProviderError>>() * 7,
        size_of::<Weak<PacketNativeImport18SelectedLaunchWireData>>(),
        size_of::<usize>() * 6,
        size_of::<Option<usize>>(),
        size_of::<[usize; 20]>(),
        size_of::<std::array::IntoIter<usize, 20>>(),
    ];
    fields.into_iter().try_fold(
        Attempt::received_loan_counter_scratch_data::<()>()?,
        |sum, field| sum.checked_add(field).ok_or_else(exhausted),
    )
}

fn refused() -> ProviderError {
    ProviderError::Correlation("original bootstrap SDK correlation refused")
}
fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("original bootstrap SDK correlation construction DATA")
}

#[cfg(test)]
#[path = "bootstrap_correlation/tests.rs"]
pub(super) mod tests;

#[path = "bootstrap_correlation/publication.rs"]
pub(super) mod publication;

#[path = "bootstrap_correlation/view.rs"]
mod view;
pub(super) use view::View;
