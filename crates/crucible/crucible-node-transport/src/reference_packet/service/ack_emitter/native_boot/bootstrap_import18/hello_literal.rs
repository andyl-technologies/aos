//! Admits and retains one actual unparsed public Hello under the original cut.

use super::*;
use crate::native_hello::OriginalNativeHelloLiteral;
use crate::reference_packet::service::PacketNative5SourceLaunch;

/// Admits the actual literal body allocation around its once-only public read.
pub(in super::super) trait OriginalImport18HelloLiteralAdmission {
    /// Admits the complete maximum body before reading the first public byte.
    ///
    /// # Errors
    /// Refuses unavailable original credit or incomplete whole-owner custody.
    fn construct_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        row: [usize; 3],
    ) -> Result<(), ProviderError>;

    /// Observes the actual surviving allocation and partial I/O on either outcome.
    ///
    /// # Errors
    /// Refuses unavailable original credit or incomplete whole-owner observation.
    fn finish_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        actual_backing: usize,
    ) -> Result<(), ProviderError>;
}

impl OriginalImport18RawBootstrap {
    /// Receives the original public Hello once without parsing or negotiation.
    ///
    /// Admission precedes the first public read. The same original socket,
    /// deadline, journal, partial body and cursors survive either outcome. A
    /// complete literal supplies DATA only; no response or model is constructed.
    ///
    /// # Errors
    /// Refuses re-entry, incomplete framing, stale original custody, unavailable
    /// admission, malformed/partial framing, I/O or terminal correspondence.
    pub(in super::super) fn receive_hello_literal_data(
        &mut self,
        admission: &dyn OriginalImport18HelloLiteralAdmission,
    ) -> Result<(), ProviderError> {
        if self.hello_literal_started {
            return Err(refused());
        }
        self.hello_literal_started = true;
        let outcome = self.receive_current_hello_literal(admission);
        let terminal = self.typed_bodies_data().map(|_| ());
        outcome?;
        terminal?;
        self.hello_literal_complete = true;
        Ok(())
    }

    fn receive_current_hello_literal(
        &mut self,
        admission: &dyn OriginalImport18HelloLiteralAdmission,
    ) -> Result<(), ProviderError> {
        self.with_hello_exchange_data(|_| Ok(()))?;
        self.admit_source_row(self.initial_construction.as_ref().ok_or_else(refused)?.row)?;
        let row = construction_data(self.typed_bodies_data()?.launch.launch_data())?;
        self.hello_literal_row = Some(row);
        admission.construct_data(self, row)?;
        let outcome = self.read_current_hello_literal();
        let terminal = self
            .hello_literal_backing_data()
            .and_then(|actual| admission.finish_data(self, actual));
        let physical = self.with_hello_exchange_data(|exchange| {
            exchange.original_stream_data().completed_data(self.cut)
        });
        outcome?;
        terminal?;
        physical
    }

    fn read_current_hello_literal(&mut self) -> Result<(), ProviderError> {
        // Recheck every physical/typed guard after admission and before I/O.
        self.with_hello_exchange_data(|_| Ok(()))?;
        self.hello_exchange
            .destination_data()
            .as_mut()
            .ok_or_else(refused)?
            .receive_literal_into_data(&mut self.hello_literal)
    }

    /// Lends the complete original body with physical and typed terminal guards.
    ///
    /// Only Copy DATA may return, and the caller separately admits inspection.
    ///
    /// # Errors
    /// Refuses incomplete/spent custody, changed literals, callback or terminal
    /// guards. Callback failure still executes both enclosing terminal guards.
    pub(in super::super) fn with_hello_literal_data<R: Copy>(
        &self,
        inspect: impl FnOnce(&[u8]) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        if !self.hello_literal_complete {
            return Err(refused());
        }
        self.with_hello_exchange_data(|exchange| {
            let literal = self.hello_literal.as_ref().ok_or_else(refused)?;
            let outcome = inspect(literal.body_data(exchange)?);
            let terminal = literal.body_data(exchange).map(|_| ());
            let result = outcome?;
            terminal?;
            Ok(result)
        })
    }

    /// Counts the actual bounded body allocation, including failed reads.
    ///
    /// # Errors
    /// Refuses foreign original ownership.
    pub(super) fn hello_literal_backing_data(&self) -> Result<usize, ProviderError> {
        self.hello_literal.as_ref().map_or(
            Ok(0),
            OriginalNativeHelloLiteral::retained_body_backing_data,
        )
    }

    /// Names separate future literal inspection and its actual Copy output.
    pub(in super::super) fn hello_literal_loan_counter_scratch_data<R: Copy>() -> usize {
        Self::hello_exchange_loan_counter_scratch_data::<R>()
            + counter_scratch_data()
            + size_of::<R>() * 2
            + size_of::<Result<R, ProviderError>>() * 2
    }
}

/// Quotes only the new actual literal body and its read controls.
///
/// # Errors
/// Refuses invalid framing or checked layout overflow.
pub(in crate::reference_packet::service) fn construction_data(
    launch: &PacketNative5SourceLaunch,
) -> Result<[usize; 3], ProviderError> {
    let maximum = usize::try_from(launch.limits.frame_bytes.get()).map_err(|_| exhausted())?;
    let mut row = OriginalNativeHelloLiteral::construction_data(maximum)?;
    row[2] = row[2]
        .checked_add(counter_scratch_data())
        .ok_or_else(exhausted)?;
    Ok(row)
}

/// Names actual admission, retained partial, enclosing guard and loan controls.
pub(in crate::reference_packet::service) fn counter_scratch_data() -> usize {
    OriginalNativeHelloLiteral::counter_scratch_data()
        + OriginalImport18RawBootstrap::hello_exchange_loan_counter_scratch_data::<()>()
        + size_of::<
            &mut crate::native_hello::OriginalNativeHelloExchange<
                crate::client::OriginalNativePublicBirthChannel,
            >,
        >()
        + size_of::<&OriginalImport18RawBootstrap>()
        + size_of::<&mut OriginalImport18RawBootstrap>()
        + size_of::<&dyn OriginalImport18HelloLiteralAdmission>()
        + size_of::<[usize; 3]>()
        + size_of::<Result<[usize; 3], ProviderError>>()
        + size_of::<&PacketNative5SourceLaunch>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<Result<(), ProviderError>>() * 5
}
