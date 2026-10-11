//! Whole prebuilt reply/proof prefixes with retained transport failure owners.
//!
//! These capsules grant no native execution or content-consumption authority.
//! An installed source retains its native owner beside the returned connection
//! and complete originals, including after publication or acknowledgement fails.

use super::*;

const MAXIMUM_EXCHANGE_BYTES: usize = 32 * 1024 * 1024;

/// Retains complete planned frames and actual acknowledgement progress.
pub struct ExchangeRecord {
    originals: Vec<Envelope>,
    canonical: Vec<Vec<u8>>,
    acknowledgements: Vec<ReceivedFrame>,
    sent: usize,
}

impl ExchangeRecord {
    /// Borrows every exact original frame, including any unsent suffix.
    pub fn originals(&self) -> &[Envelope] {
        &self.originals
    }

    /// Borrows complete original canonical frame bytes without reencoding.
    pub fn canonical_frames(&self) -> &[Vec<u8>] {
        &self.canonical
    }

    /// Borrows actually received replies, never prospective acknowledgements.
    pub fn acknowledgements(&self) -> &[ReceivedFrame] {
        &self.acknowledgements
    }

    /// Counts whole frame writes without asserting native or durable custody.
    pub fn sent(&self) -> usize {
        self.sent
    }
}

/// Owns one connection and its entire prebuilt response/proof prefix.
///
/// All canonical buffers, original correlation copies and acknowledgement list
/// slots precede any source callback. Native effects must remain under separate
/// source custody; completing this exchange does not acknowledge native output.
#[must_use = "retain the original exchange alongside its independent native owner"]
pub struct PreparedExchange<S: ProviderStream> {
    connection: Connection<S>,
    record: ExchangeRecord,
    phase: Phase,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Unprepared,
    Prepared,
    Publishing,
    Complete,
    Failed,
}

/// Retains a failed exchange and its fenced original connection.
///
/// The source owner must retain this capsule, complete native operations and
/// original body custody until authentic reconciliation or reclamation.
#[must_use = "failed transport preserves original exchange and native uncertainty"]
pub struct ExchangeFailure<S: ProviderStream> {
    connection: Connection<S>,
    record: ExchangeRecord,
    error: ProviderError,
}

impl<S: ProviderStream> ExchangeFailure<S> {
    /// Borrows the actual failure without inferring absence of native effects.
    pub fn error(&self) -> &ProviderError {
        &self.error
    }

    /// Borrows the original complete exchange and actual received prefix.
    pub fn record(&self) -> &ExchangeRecord {
        &self.record
    }

    /// Moves the same fenced connection and originals into a retained owner.
    pub fn into_parts(self) -> (Connection<S>, ExchangeRecord, ProviderError) {
        (self.connection, self.record, self.error)
    }
}

impl<S: ProviderStream> Connection<S> {
    /// Prebuilds and registers a whole original prefix before source effects.
    ///
    /// The input is already owned by the caller. Before additional encoding or
    /// correlation copies, every frame is sized against negotiated limits and
    /// the independent 32 MiB aggregate cap. The complete prefix must fit the
    /// simultaneous outgoing correlation allowance; serial writes cannot borrow
    /// future credit. Existing single-frame send semantics remain unchanged.
    ///
    /// # Errors
    /// Returns the same fenced connection and complete original list for invalid
    /// scope/body/sequence, insufficient whole-prefix credit or revoked authority.
    /// Preparation failure performs no transport write or native callback.
    pub fn prepare_exchange(
        self,
        originals: Vec<Envelope>,
    ) -> Result<PreparedExchange<S>, Box<ExchangeFailure<S>>> {
        let mut exchange = self.unprepared_exchange(originals);
        if let Err(error) = exchange.prepare_in_place() {
            return Err(exchange.fail(error, ConnectionFailure::Protocol));
        }
        Ok(exchange)
    }

    pub(crate) fn unprepared_exchange(self, originals: Vec<Envelope>) -> PreparedExchange<S> {
        PreparedExchange {
            connection: self,
            record: ExchangeRecord {
                originals,
                canonical: Vec::new(),
                acknowledgements: Vec::new(),
                sent: 0,
            },
            phase: Phase::Unprepared,
        }
    }
}

impl<S: ProviderStream> PreparedExchange<S> {
    /// Borrows complete originals and actual progress under the same owner.
    pub fn record(&self) -> &ExchangeRecord {
        &self.record
    }

    pub(crate) fn prepare_in_place(&mut self) -> Result<(), ProviderError> {
        if self.phase != Phase::Unprepared {
            return Err(ProviderError::Conflict(
                "original exchange preparation already attempted",
            ));
        }
        // Installed schema/supervision code can unwind. The owning endpoint
        // installs this capsule outside the callback before invoking this seam.
        self.phase = Phase::Failed;
        let result = self.prepare();
        if result.is_ok() {
            self.phase = Phase::Prepared;
        } else {
            self.connection.contain(ConnectionFailure::Protocol);
        }
        result
    }

    fn prepare(&mut self) -> Result<(), ProviderError> {
        self.connection.check_authority()?;
        let limits = self.connection.authority.limits();
        let maximum_frame = allowance(limits.frame_bytes.get())?;
        let maximum_requests = allowance(limits.requests.get())?;
        let count = self.record.originals.len();
        let requests = self
            .record
            .originals
            .iter()
            .filter(|original| original.message == MessageKind::Request)
            .count();
        if count == 0 || count > maximum_requests.saturating_add(1) || requests > maximum_requests {
            return Err(ProviderError::ResourceExhausted(
                "prepared exchange frame count",
            ));
        }

        let mut total = 0usize;
        for original in &self.record.originals {
            let bytes = super::prepared::serialized_credit(original, maximum_frame)?;
            total = total
                .checked_add(bytes)
                .filter(|total| *total <= MAXIMUM_EXCHANGE_BYTES)
                .ok_or(ProviderError::ResourceExhausted(
                    "prepared exchange whole bytes",
                ))?;
        }
        self.record
            .canonical
            .try_reserve_exact(count)
            .map_err(|_| ProviderError::ResourceExhausted("prepared frame slots"))?;
        self.record
            .acknowledgements
            .try_reserve_exact(requests)
            .map_err(|_| ProviderError::ResourceExhausted("prepared acknowledgement slots"))?;

        for original in &self.record.originals {
            self.connection.validate_body(original, false)?;
            let value = serde_json::to_value(original)
                .map_err(crucible_node_contract::ContractError::from)?;
            let bytes = canonical::canonical_json(&value)?;
            canonical::parse_json_with_depth(
                &bytes,
                maximum_frame,
                allowance(limits.nesting.get())?,
            )?;
            self.record.canonical.push(bytes);
        }
        for original in &self.record.originals {
            self.connection
                .authority
                .with_live(|| self.connection.guard.register_outgoing(original.clone()))?;
        }
        Ok(())
    }

    /// Publishes retained bytes and receives each exact original proof response.
    ///
    /// The supplied source validator checks transfer semantics beyond baseline
    /// response correlation. Received replies remain in this borrowed owner even
    /// if validation refuses or unwinds. A scoped guard fences the connection on
    /// every incomplete attempt. Neither retry nor error can resend this prefix.
    /// Remote parsing retains existing finite limits and allocator constraints.
    ///
    /// # Errors
    /// Keeps the complete original owner on I/O, malformed/foreign traffic,
    /// unexpected requests, source disagreement or a second publication attempt.
    pub fn publish(
        &mut self,
        validate: &mut dyn FnMut(&Envelope, &ReceivedFrame) -> Result<(), ProviderError>,
    ) -> Result<(), ProviderError> {
        if self.phase != Phase::Prepared {
            return Err(ProviderError::Conflict(
                "prepared exchange already attempted",
            ));
        }
        self.phase = Phase::Publishing;
        let mut attempt = PublicationAttempt {
            connection: &mut self.connection,
            complete: false,
        };
        let result = publish(attempt.connection, &mut self.record, validate);
        if result.is_ok() {
            self.phase = Phase::Complete;
            attempt.complete = true;
        } else {
            self.phase = Phase::Failed;
        }
        result
    }

    /// Moves the same connection and full records into the source's owning ledger.
    ///
    /// Success discharges transport correlation only. A failed or unwound
    /// publication returns its already fenced original connection and progress.
    pub fn into_parts(mut self) -> (Connection<S>, ExchangeRecord) {
        if self.phase != Phase::Complete {
            self.connection.contain(ConnectionFailure::Closed);
        }
        (self.connection, self.record)
    }

    /// Fences an unpublished prospective prefix while retaining every original.
    pub fn abort(self, error: ProviderError) -> Box<ExchangeFailure<S>> {
        self.fail(error, ConnectionFailure::Closed)
    }

    fn fail(mut self, error: ProviderError, failure: ConnectionFailure) -> Box<ExchangeFailure<S>> {
        self.connection.contain(failure);
        Box::new(ExchangeFailure {
            connection: self.connection,
            record: self.record,
            error,
        })
    }
}

struct PublicationAttempt<'a, S: ProviderStream> {
    connection: &'a mut Connection<S>,
    complete: bool,
}

impl<S: ProviderStream> Drop for PublicationAttempt<'_, S> {
    fn drop(&mut self) {
        if !self.complete {
            self.connection.contain(ConnectionFailure::Protocol);
        }
    }
}

fn publish<S: ProviderStream>(
    connection: &mut Connection<S>,
    record: &mut ExchangeRecord,
    validate: &mut dyn FnMut(&Envelope, &ReceivedFrame) -> Result<(), ProviderError>,
) -> Result<(), ProviderError> {
    for index in 0..record.originals.len() {
        connection.check_authority()?;
        let bytes = &record.canonical[index];
        let length = u32::try_from(bytes.len())
            .map_err(|_| ProviderError::Frame("prepared exchange frame length"))?;
        let stream = connection.reader.stream_mut();
        if let Err(error) = stream
            .write_all(&length.to_be_bytes())
            .and_then(|()| stream.write_all(bytes))
        {
            connection.contain(ConnectionFailure::Write);
            return Err(error.into());
        }
        record.sent += 1;
        let original = &record.originals[index];
        if original.message == MessageKind::Response {
            connection.guard.confirm_response_sent(original)?;
        } else if original.message == MessageKind::Request {
            let reply = connection
                .receive()?
                .ok_or(ProviderError::Frame("prepared proof reply missing"))?;
            record.acknowledgements.push(reply);
            let reply = record
                .acknowledgements
                .last()
                .ok_or(ProviderError::Frame("retained proof reply absent"))?;
            if reply.envelope.message != MessageKind::Response {
                return Err(ProviderError::Correlation(
                    "expected original proof response",
                ));
            }
            original.matches_response(&reply.envelope)?;
            validate(original, reply)?;
        }
    }
    Ok(())
}
