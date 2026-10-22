//! Retains bounded canonical response bytes and the original publication attempt.
//!
//! Fixed destinations precede private receipt. Encoding never clones the body
//! DOM; partial encoded bytes and typed failures survive every terminal refusal.

use super::*;
use crate::envelope::Envelope;
use crate::native_hello::{
    OriginalNativeHelloExchange, OriginalNativeHelloLiteral, OriginalNativeHelloPublication,
    RetainedOriginalNativeHelloExchange,
};
use crate::protocol_snapshot::ProtocolCaptureOwner;
use crucible_node_format::ContractError;
use std::io::{self, Read, Write};

/// Retains original encoding, failure and publication custody before private receipt.
pub(in super::super) struct Attempt {
    owner: ProtocolCaptureOwner,
    stage: Stage,
    cut: Option<OperationalDeadline>,
    quote: Option<Quote>,
    body: Vec<u8>,
    failure: Option<Failure>,
    publication: OriginalNativeHelloPublication,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Stage {
    Empty,
    Inspecting,
    Quoted,
    Encoding,
    Encoded,
    Publishing,
    Published,
    Complete,
    Failed,
}

enum Failure {
    Native(ProviderError),
    Json {
        category: serde_json::error::Category,
        line: usize,
        column: usize,
    },
}

const _: fn(&Attempt) = |value| {
    let Attempt {
        owner: _,
        stage: _,
        cut: _,
        quote: _,
        body: _,
        failure: _,
        publication: _,
    } = value;
};

impl Attempt {
    /// Installs all physical destinations before any bootstrap input read.
    pub(in super::super) fn empty_data() -> Self {
        Self {
            owner: ProtocolCaptureOwner::new(),
            stage: Stage::Empty,
            cut: None,
            quote: None,
            body: Vec::new(),
            failure: None,
            publication: OriginalNativeHelloPublication::empty_data(),
        }
    }

    /// Spends before quote, original guards or admission callbacks.
    ///
    /// # Errors
    /// Refuses foreign custody or a previously spent occurrence.
    pub(super) fn start_data(&mut self, cut: OperationalDeadline) -> Result<(), ProviderError> {
        self.owner.ensure_current()?;
        if self.stage != Stage::Empty {
            return Err(refused());
        }

        self.stage = Stage::Inspecting;
        self.cut = Some(cut);
        Ok(())
    }

    /// Stores the independent full quote before allocation or publication.
    ///
    /// # Errors
    /// Refuses wrong stage, occupied quote or expired/substituted custody.
    pub(super) fn quote_data(
        &mut self,
        quote: Quote,
        cut: OperationalDeadline,
    ) -> Result<(), ProviderError> {
        self.guard(cut)?;
        if self.stage != Stage::Inspecting || self.quote.is_some() {
            return Err(refused());
        }

        self.quote = Some(quote);
        self.stage = Stage::Quoted;
        Ok(())
    }

    /// Encodes the original borrowed envelope into its bounded retained bank.
    ///
    /// # Errors
    /// Refuses missing quote, re-entry, custody, allocation, canonical grammar,
    /// sink overflow or terminal expiry. Every initialized byte stays owned.
    pub(super) fn encode_data(
        &mut self,
        response: &Envelope,
        cut: OperationalDeadline,
    ) -> Result<(), ProviderError> {
        self.guard(cut)?;
        if self.stage != Stage::Quoted || !self.body.is_empty() || self.failure.is_some() {
            return Err(refused());
        }

        let maximum = self.quote.as_ref().ok_or_else(refused)?.maximum_body;
        self.stage = Stage::Encoding;
        self.body
            .try_reserve_exact(maximum)
            .map_err(|_| refused())?;
        if self.body.capacity() != maximum {
            return Err(refused());
        }

        let outcome = crate::native_hello::write_canonical_hello_response_data(
            response,
            &mut BodyWriter {
                body: &mut self.body,
                maximum,
            },
        );

        if let Err(error) = outcome {
            self.failure = Some(match error {
                ProviderError::Contract(ContractError::Json(error)) => Failure::Json {
                    category: error.classify(),
                    line: error.line(),
                    column: error.column(),
                },
                error => Failure::Native(error),
            });
            return Err(refused());
        }
        self.guard(cut)?;
        self.stage = Stage::Encoded;
        Ok(())
    }

    /// Publishes this original complete proposal through the same actual exchange.
    ///
    /// # Errors
    /// Refuses wrong stage, custody, original literal, publication or final cut.
    pub(super) fn publish_data<S: Read + Write>(
        &mut self,
        exchange: &mut RetainedOriginalNativeHelloExchange<S>,
        literal: &OriginalNativeHelloLiteral,
        cut: OperationalDeadline,
    ) -> Result<(), ProviderError> {
        self.guard(cut)?;
        if self.stage != Stage::Encoded || self.failure.is_some() {
            return Err(refused());
        }

        self.stage = Stage::Publishing;
        exchange.publish_literal_response_data(literal, &self.body, &mut self.publication, cut)?;
        self.guard(cut)?;
        self.stage = Stage::Published;
        Ok(())
    }

    /// Completes only after original guards, live lease and terminal census.
    ///
    /// # Errors
    /// Refuses another stage, an absent quote or expired/substituted custody.
    pub(super) fn complete_data(&mut self, cut: OperationalDeadline) -> Result<(), ProviderError> {
        self.guard(cut)?;
        if self.stage != Stage::Published || self.quote.is_none() {
            return Err(refused());
        }

        self.stage = Stage::Complete;
        Ok(())
    }

    /// Retains all initialized output and publication owners while refusing retry.
    pub(super) fn refuse_data(&mut self) {
        self.stage = Stage::Failed;
    }

    /// Borrows completed proposal DATA without moving an allocation or lease.
    ///
    /// # Errors
    /// Refuses an incomplete/refused phase or expired/substituted custody.
    pub(super) fn body_data(&self, cut: OperationalDeadline) -> Result<&[u8], ProviderError> {
        self.guard(cut)?;
        if self.stage != Stage::Complete || self.failure.is_some() {
            return Err(refused());
        }
        Ok(&self.body)
    }

    /// Reads physical role digests only after complete enclosing publication.
    ///
    /// # Errors
    /// Refuses incomplete/refused output, original cut/bank changes or partial
    /// physical frames. The enclosing root additionally authenticates its SDK lease.
    pub(in super::super) fn frame_digests_data<S: Read + Write>(
        &self,
        exchange: &OriginalNativeHelloExchange<S>,
        cut: OperationalDeadline,
    ) -> Result<crate::hello_frames::OriginalHelloFrameDigests, ProviderError> {
        self.body_data(cut)?;
        self.publication.completed_frame_digests_data(exchange, cut)
    }

    /// Borrows the original stream only after this exact completed publication.
    ///
    /// The caller admits effects and retains every partial before entry.
    ///
    /// # Errors
    /// Refuses incomplete publication, changed original pair/cut, callback or
    /// terminal owner correspondence.
    pub(in super::super) fn with_completed_stream_data<S: Read + Write, R: Copy>(
        &self,
        exchange: &mut RetainedOriginalNativeHelloExchange<S>,
        cut: OperationalDeadline,
        inspect: impl FnOnce(&mut S) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        self.body_data(cut)?;
        let outcome =
            exchange.with_completed_publication_stream_data(&self.publication, cut, inspect);
        let terminal = self.body_data(cut).map(|_| ());
        let result = outcome?;
        terminal?;
        Ok(result)
    }

    /// Quotes the actual completed-publication adapter and nested stream loan.
    ///
    /// # Errors
    /// Refuses checked accumulation overflow.
    pub(in super::super) fn completed_stream_counter_scratch_data<S: Read + Write, R: Copy>()
    -> Result<usize, ProviderError> {
        [
            Self::counter_scratch_data::<S>(),
            size_of::<&Self>(),
            size_of::<&mut RetainedOriginalNativeHelloExchange<S>>(),
            size_of::<OperationalDeadline>(),
            size_of::<Result<&[u8], ProviderError>>(),
            size_of::<Result<R, ProviderError>>(),
            size_of::<Result<R, ProviderError>>(),
            size_of::<Result<(), ProviderError>>(),
        ]
        .into_iter()
        .try_fold(
            RetainedOriginalNativeHelloExchange::<S>::publication_stream_counter_scratch_data::<R>(
            )?,
            |sum, field| sum.checked_add(field).ok_or_else(refused),
        )
    }

    /// Counts initialized backing independently of phase completion and expiry.
    ///
    /// # Errors
    /// Refuses foreign custody, missing exchange for a bound publication, unknown
    /// custom I/O ownership, unsupported diagnostic layout or checked overflow.
    pub(super) fn retained_backing_data<S: Read + Write>(
        &self,
        exchange: Option<&OriginalNativeHelloExchange<S>>,
    ) -> Result<usize, ProviderError> {
        self.owner.ensure_current()?;
        let publication = match exchange {
            Some(exchange) => self
                .publication
                .retained_backing_beside_exchange_data(exchange)?,
            None => self.publication.retained_backing_before_exchange_data()?,
        };

        let diagnostic = match &self.failure {
            Some(Failure::Native(ProviderError::Contract(ContractError::Invalid {
                reason,
                ..
            }))) => reason.capacity(),
            Some(Failure::Native(ProviderError::Io(error))) if error.get_ref().is_none() => 0,
            Some(Failure::Native(ProviderError::Io(_)))
            | Some(Failure::Native(ProviderError::Contract(ContractError::Json(_)))) => {
                return Err(refused());
            }
            None
            | Some(Failure::Native(ProviderError::Contract(ContractError::Overflow)))
            | Some(Failure::Native(ProviderError::Frame(_)))
            | Some(Failure::Native(ProviderError::Correlation(_)))
            | Some(Failure::Native(ProviderError::ResourceExhausted(_)))
            | Some(Failure::Native(ProviderError::Conflict(_)))
            | Some(Failure::Json {
                category: _,
                line: _,
                column: _,
            }) => 0,
        };

        self.body
            .capacity()
            .checked_add(diagnostic)
            .and_then(|n| n.checked_add(publication))
            .ok_or_else(refused)
    }

    /// Names actual encoder, retained failure, bounded sink and original I/O controls.
    pub(super) fn counter_scratch_data<S: Read + Write>() -> usize {
        OriginalNativeHelloPublication::counter_scratch_data::<S>()
            + RetainedOriginalNativeHelloExchange::<S>::publication_counter_scratch_data()
            + size_of::<&Self>() * 3
            + size_of::<&mut Self>() * 3
            + size_of::<&Envelope>()
            + size_of::<&OriginalNativeHelloLiteral>()
            + size_of::<BodyWriter<'static>>() * 2
            + size_of::<&mut BodyWriter<'static>>()
            + size_of::<&mut Vec<u8>>()
            + size_of::<&[u8]>() * 3
            + size_of::<OperationalDeadline>() * 3
            + size_of::<Quote>()
            + size_of::<Option<Quote>>()
            + size_of::<Stage>()
            + size_of::<Option<Failure>>()
            + size_of::<ProviderError>()
            + size_of::<Option<ProviderError>>()
            + size_of::<serde_json::error::Category>()
            + size_of::<usize>() * 5
            + size_of::<Option<usize>>() * 2
            + size_of::<Result<(), std::collections::TryReserveError>>()
            + size_of::<Result<(), ProviderError>>() * 5
            + size_of::<Result<usize, ProviderError>>() * 3
            + size_of::<Result<usize, io::Error>>()
            + size_of::<Result<&'static [u8], ProviderError>>()
    }

    fn guard(&self, cut: OperationalDeadline) -> Result<(), ProviderError> {
        self.owner.ensure_current()?;
        if self.cut != Some(cut) || cut.is_expired() {
            return Err(refused());
        }
        Ok(())
    }

    #[cfg(test)]
    pub(in super::super) fn row_fixture_data(&self) -> Option<[usize; 3]> {
        self.quote.map(|quote| quote.row)
    }
}

/// Borrows the already reserved output bank without permitting allocation.
pub(super) struct BodyWriter<'a> {
    body: &'a mut Vec<u8>,
    maximum: usize,
}

impl Write for BodyWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next = self
            .body
            .len()
            .checked_add(bytes.len())
            .filter(|next| *next <= self.maximum)
            .ok_or(io::ErrorKind::Other)?;
        if next > self.body.capacity() {
            return Err(io::ErrorKind::Other.into());
        }
        self.body.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
