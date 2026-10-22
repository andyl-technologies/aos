//! Retains one post-Hello frame under the original bootstrap socket and cut.
//!
//! The external attempt owns the complete literal bank and every failed read
//! prefix beside the original receiver. Raw receipt supplies DATA only: no JSON
//! parser, assigned SDK request, Source grant, ACK or native model is produced.
//!
//! ```text
//! literal = uint32_be(body_length) || unparsed_body
//! ```

use super::bootstrap_normalizations::Attempt as Normalizations;
use super::bootstrap_operands::BootstrapAckOperands;
use super::*;
use crate::client::OriginalNativePublicBirthChannel;
use crate::reference_packet::service::PacketNative5SourceLaunch;
use crate::reference_packet::service::complete_restore::import18::PacketNativeImport18SelectedLaunchWireData;
use std::{
    io::{self, Read},
    rc::{Rc, Weak},
};

/// Admits and observes the original receiver and both external attempt owners.
pub(in super::super) trait Admission {
    /// Admits the stored complete read row before allocation or public I/O.
    ///
    /// Callback allocation and errors remain separately funded by the caller.
    ///
    /// # Errors
    /// Refuses missing original credit or an incomplete whole-owner census.
    fn construct_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        normalizations: &Normalizations,
        attempt: &Attempt,
        row: [usize; 3],
    ) -> Result<(), ProviderError>;

    /// Observes the actual surviving bank and read cursors on either outcome.
    ///
    /// # Errors
    /// Refuses unavailable credit or incomplete whole-owner observation.
    fn finish_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        normalizations: &Normalizations,
        attempt: &Attempt,
        actual: usize,
    ) -> Result<(), ProviderError>;
}

/// Retains a single complete or failed raw bootstrap-frame occurrence.
pub(in super::super) struct Attempt {
    started: bool,
    complete: bool,
    failed: bool,
    cut: Option<OperationalDeadline>,
    launch: Option<Weak<PacketNativeImport18SelectedLaunchWireData>>,
    row: Option<[usize; 3]>,
    bank: Vec<u8>,
    received: usize,
    digest: Option<[u8; 32]>,
}

impl Attempt {
    /// Initializes empty retained slots without allocating or reading.
    pub(in super::super) fn empty_data() -> Self {
        Self {
            started: false,
            complete: false,
            failed: false,
            cut: None,
            launch: None,
            row: None,
            bank: Vec::new(),
            received: 0,
            digest: None,
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

    fn guard(&self, original: &OriginalImport18RawBootstrap) -> Result<(), ProviderError> {
        self.authenticate_alias(original)?;
        if self.cut != Some(original.cut) || original.cut.is_expired() {
            return Err(refused());
        }
        original.authenticate_channel()
    }

    /// Counts the actual surviving bank even after I/O or deadline refusal.
    ///
    /// The Weak edge aliases only the checked original launch allocation.
    ///
    /// # Errors
    /// Refuses foreign launch association or checked capacity overflow.
    pub(in super::super) fn retained_requested_bytes_data(
        &self,
        original: &OriginalImport18RawBootstrap,
    ) -> Result<usize, ProviderError> {
        self.authenticate_alias(original)?;
        size_of::<Self>()
            .checked_add(self.bank.capacity())
            .ok_or_else(exhausted)
    }

    fn read(&mut self, stream: &mut impl Read, maximum: usize) -> Result<(), ProviderError> {
        let capacity = maximum.checked_add(4).ok_or_else(exhausted)?;
        self.bank
            .try_reserve_exact(capacity)
            .map_err(|_| exhausted())?;
        if self.bank.capacity() != capacity {
            return Err(exhausted());
        }
        self.bank.resize(4, 0);
        read_into(stream, &mut self.bank, &mut self.received)?;
        let header: [u8; 4] = self.bank[..4].try_into().map_err(|_| refused())?;
        let length = usize::try_from(u32::from_be_bytes(header)).map_err(|_| exhausted())?;
        if length == 0 || length > maximum {
            return Err(ProviderError::Frame("length outside admitted allowance"));
        }
        self.bank
            .resize(length.checked_add(4).ok_or_else(exhausted)?, 0);
        read_into(stream, &mut self.bank, &mut self.received)?;
        self.digest = Some(*blake3::hash(&self.bank).as_bytes());
        Ok(())
    }

    /// Quotes full original guards, literal hashing and a concrete Copy result.
    ///
    /// Callback allocation remains an independent enclosing admission.
    ///
    /// # Errors
    /// Refuses checked accumulation overflow.
    pub(in super::super) fn body_loan_counter_scratch_data<R: Copy>() -> Result<usize, ProviderError>
    {
        [
            size_of::<&Self>(),
            size_of::<&OriginalImport18RawBootstrap>(),
            size_of::<&Normalizations>(),
            size_of::<&[u8]>(),
            size_of::<&BootstrapAckOperands<'static>>(),
            size_of::<super::bootstrap_normalizations::Digests>() * 2,
            size_of::<R>(),
            size_of::<Result<R, ProviderError>>(),
            size_of::<R>(),
            size_of::<R>(),
            size_of::<Result<R, ProviderError>>(),
            size_of::<Result<R, ProviderError>>(),
            size_of::<Result<(), ProviderError>>(),
            size_of::<blake3::Hasher>(),
            size_of::<blake3::Hash>(),
            size_of::<Result<(), ProviderError>>(),
        ]
        .into_iter()
        .try_fold(
            Normalizations::host_loan_counter_scratch_data::<R>()?,
            |sum, field| sum.checked_add(field).ok_or_else(exhausted),
        )
    }

    /// Lends the received unparsed body under original Host/SDK and literal guards.
    ///
    /// Inspection and its Copy result require independent enclosing admission.
    ///
    /// # Errors
    /// Refuses incomplete/refused input, changed original custody/literal bytes,
    /// stale SDK/cut, callback refusal or a failed terminal guard.
    pub(in super::super) fn with_body_data<R: Copy>(
        &self,
        original: &OriginalImport18RawBootstrap,
        normalizations: &Normalizations,
        inspect: impl FnOnce(&[u8]) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        self.with_body_and_operands_data(original, normalizations, |raw, _, _| inspect(raw))
    }

    /// Lends the literal and same borrowed live SDK inside one full original loan.
    ///
    /// Composite DATA consumers recheck that authority between callbacks; the
    /// complete original Host/SDK guards still surround either final outcome.
    ///
    /// # Errors
    /// Preserves every literal, original, SDK, callback and terminal refusal.
    pub(super) fn with_body_and_operands_data<R: Copy>(
        &self,
        original: &OriginalImport18RawBootstrap,
        normalizations: &Normalizations,
        inspect: impl FnOnce(
            &[u8],
            &BootstrapAckOperands<'_>,
            super::bootstrap_normalizations::Digests,
        ) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        if !self.complete || self.failed || self.received != self.bank.len() {
            return Err(refused());
        }
        normalizations.with_host_bound_operands_data(original, |operands, digests| {
            self.guard(original)?;
            if self.bank.len() <= 4 || self.digest != Some(*blake3::hash(&self.bank).as_bytes()) {
                return Err(refused());
            }
            let outcome = inspect(&self.bank[4..], operands, digests);
            let terminal = self.guard(original);
            let result = outcome?;
            terminal?;
            Ok(result)
        })
    }
}

fn read_into(
    stream: &mut impl Read,
    bytes: &mut [u8],
    received: &mut usize,
) -> Result<(), ProviderError> {
    while *received < bytes.len() {
        let count = match stream.read(&mut bytes[*received..]) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if count == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
        }
        *received = received
            .checked_add(count)
            .filter(|used| *used <= bytes.len())
            .ok_or_else(exhausted)?;
    }
    Ok(())
}

impl OriginalImport18RawBootstrap {
    /// Receives the first post-Hello literal once without parsing or dispatching.
    ///
    /// Completed original normalizations and full Host-plan correspondence are
    /// required before admission and I/O. The original socket stays inside its
    /// existing Hello capsule. Failed input and both spent occurrences survive;
    /// every read outcome receives terminal SDK/cut guards and whole-owner census.
    ///
    /// # Errors
    /// Refuses retry, incomplete or stale originals, short credit, allocation,
    /// malformed/partial framing, I/O, admission or terminal correspondence.
    pub(in super::super) fn receive_bootstrap_literal_data(
        &mut self,
        normalizations: &Normalizations,
        attempt: &mut Attempt,
        admission: &dyn Admission,
    ) -> Result<(), ProviderError> {
        if self.bootstrap_literal_started || attempt.started {
            return Err(refused());
        }
        self.bootstrap_literal_started = true;
        attempt.started = true;
        let outcome = self.receive_current_bootstrap_literal(normalizations, attempt, admission);
        let terminal = self.authenticate_channel();
        if let Err(error) = outcome.and(terminal) {
            attempt.failed = true;
            let _ = self.hello_registrar.contain_admission_data();
            return Err(error);
        }
        attempt.complete = true;
        Ok(())
    }

    fn receive_current_bootstrap_literal(
        &mut self,
        normalizations: &Normalizations,
        attempt: &mut Attempt,
        admission: &dyn Admission,
    ) -> Result<(), ProviderError> {
        normalizations.with_host_bound_digests_data(self, |_| Ok(()))?;
        attempt.cut = Some(self.cut);
        attempt.launch = Some(Rc::downgrade(self.parsed.shared_launch_data()?));
        let launch = self.typed_bodies_data()?.launch.launch_data();
        let maximum = maximum_data(launch)?;
        let row = construction_data(launch, self.bounds.requested_peak)?;
        attempt.row = Some(row);
        let whole = [
            self.retained_requested_bytes()?
                .checked_add(normalizations.retained_requested_bytes_data(self)?)
                .and_then(|bytes| bytes.checked_add(row[0]))
                .ok_or_else(exhausted)?,
            row[1],
            row[2],
        ];
        self.admit_source_row(whole)?;
        admission.construct_data(self, normalizations, attempt, row)?;
        normalizations.with_host_bound_digests_data(self, |_| attempt.guard(self))?;

        let outcome = self.hello_publication.with_completed_stream_data(
            self.hello_exchange
                .destination_data()
                .as_mut()
                .ok_or_else(refused)?,
            self.cut,
            |stream| attempt.read(stream, maximum),
        );
        let terminal = normalizations.with_host_bound_digests_data(self, |_| attempt.guard(self));
        let census = attempt
            .retained_requested_bytes_data(self)
            .and_then(|actual| admission.finish_data(self, normalizations, attempt, actual));
        let observed = normalizations.with_host_bound_digests_data(self, |_| attempt.guard(self));
        outcome?;
        terminal?;
        census?;
        observed
    }
}

fn maximum_data(launch: &PacketNative5SourceLaunch) -> Result<usize, ProviderError> {
    let maximum = usize::try_from(launch.limits.frame_bytes.get()).map_err(|_| exhausted())?;
    if maximum == 0 || maximum > crate::transport::MAX_FRAME_BYTES {
        return Err(refused());
    }
    Ok(maximum)
}

/// Quotes the single retained literal bank and actual original read controls.
///
/// This row creates no read allowance or enclosing Source/Birth permission.
///
/// # Errors
/// Refuses invalid negotiated limits, checked overflow or the complete restriction.
pub(in crate::reference_packet::service) fn construction_data(
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
) -> Result<[usize; 3], ProviderError> {
    let row = [
        size_of::<Attempt>()
            .checked_add(maximum_data(launch)?)
            .and_then(|bytes| bytes.checked_add(4))
            .ok_or_else(exhausted)?,
        size_of::<Attempt>() + size_of::<Result<Attempt, ProviderError>>(),
        counter_scratch_data()?,
    ];
    if row
        .into_iter()
        .try_fold(0usize, usize::checked_add)
        .is_none_or(|sum| sum > maximum)
    {
        return Err(exhausted());
    }
    Ok(row)
}

fn counter_scratch_data() -> Result<usize, ProviderError> {
    [
        OriginalNativePublicBirthChannel::read_counter_scratch_data(),
        super::hello_publication::Attempt::completed_stream_counter_scratch_data::<
            OriginalNativePublicBirthChannel,
            (),
        >()?,
        size_of::<Attempt>(),
        size_of::<&mut Attempt>(),
        size_of::<&Attempt>(),
        size_of::<&mut OriginalImport18RawBootstrap>(),
        size_of::<&OriginalImport18RawBootstrap>(),
        size_of::<&Normalizations>(),
        size_of::<&dyn Admission>(),
        size_of::<&mut Vec<u8>>(),
        size_of::<&mut [u8]>(),
        size_of::<&[u8]>(),
        size_of::<&mut usize>(),
        size_of::<[u8; 4]>(),
        size_of::<[usize; 3]>() * 2,
        size_of::<Result<[usize; 3], ProviderError>>(),
        size_of::<usize>() * 6,
        size_of::<Option<usize>>(),
        size_of::<io::Result<usize>>(),
        size_of::<Result<(), ProviderError>>() * 6,
        size_of::<std::collections::TryReserveError>(),
        size_of::<Result<(), std::collections::TryReserveError>>(),
        size_of::<blake3::Hasher>(),
        size_of::<blake3::Hash>(),
        size_of::<Weak<PacketNativeImport18SelectedLaunchWireData>>(),
    ]
    .into_iter()
    .try_fold(
        Normalizations::host_loan_counter_scratch_data::<()>()?,
        |sum, field| sum.checked_add(field).ok_or_else(exhausted),
    )
    .and_then(|construction| Ok(construction.max(Attempt::body_loan_counter_scratch_data::<()>()?)))
}

#[cfg(test)]
#[path = "bootstrap_literal/tests.rs"]
pub(super) mod tests;
