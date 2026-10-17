//! Finite data-only observations of explicit retained-original wire resends.
//!
//! Rows distinguish attempted write, completed write and received decoded frame.
//! Encodings are canonical envelopes, not arbitrary raw stream history. A
//! completed row requires an actual new send/read and an unchanged semantic
//! response. These observations grant no execution, ACK or qualification.

use std::sync::{Arc, Mutex};

use crucible_node_contract::{Bytes, HashRef, Id, U64, canonical};
use serde::Serialize;

use crate::{
    ProviderError,
    envelope::{Envelope, RequestOrigin},
    handshake::ConnectionAuthority,
};

#[cfg(test)]
#[path = "transmissions_tests.rs"]
mod tests;

const MAXIMUM_TRANSMISSIONS: usize = 16;
const MAXIMUM_BYTES: usize = 64 * 1024 * 1024;

/// Bounds the complete archive before any selected original request is sent.
#[derive(Clone, Copy)]
pub struct TransmissionLimits {
    /// Bounds attempted resends, including failed and unresolved transmissions.
    pub maximum_transmissions: usize,
    /// Bounds request plus reserved response bytes over the archive lifetime.
    pub maximum_bytes: usize,
}

/// Exposes immutable data reads without a controller or socket accessor.
#[derive(Clone)]
pub struct TransmissionObservationHandle {
    archive: Arc<Mutex<Archive>>,
}

pub(crate) struct TransmissionRecorder {
    private_token: Bytes,
    archive: Arc<Mutex<Archive>>,
}

#[derive(Clone, Serialize)]
struct Scope {
    session: Id,
    incarnation: Id,
    connection: Id,
}

#[derive(Clone, Serialize)]
struct Row {
    transmission: U64,
    origin: RequestOrigin,
    request_id: Id,
    identity: HashRef,
    sent_sequence: U64,
    write_completed: bool,
    semantic_response_verified: bool,
    request_start: usize,
    request_length: usize,
    received: Option<(usize, usize)>,
}

struct Archive {
    scope: Scope,
    rows: Vec<Row>,
    bytes: Vec<u8>,
    maximum_transmissions: usize,
    maximum_bytes: usize,
    reserved_bytes: usize,
    incomplete: bool,
}

/// Retains a bounded snapshot of actual explicit resend transmissions.
#[derive(Serialize)]
pub struct TransmissionObservation {
    schema: &'static str,
    encoding: &'static str,
    scope: Scope,
    rows: Vec<Row>,
    bytes: Bytes,
    incomplete: bool,
}

impl TransmissionObservationHandle {
    /// Copies retained canonical controls under a separate finite data-read cap.
    ///
    /// # Errors
    /// Refuses poisoned storage or a byte cap smaller than the retained data.
    pub fn snapshot(&self, maximum_bytes: usize) -> Result<TransmissionObservation, ProviderError> {
        let archive = self
            .archive
            .lock()
            .map_err(|_| refused("transmission archive poisoned"))?;
        if maximum_bytes == 0
            || maximum_bytes > MAXIMUM_BYTES
            || archive.bytes.len() > maximum_bytes
        {
            return Err(exhausted("selected transmission byte ceiling"));
        }
        Ok(TransmissionObservation {
            schema: "crucible.reference.original-wire-resends.v1",
            encoding: "canonical-transmitted-and-decoded-envelope-v1",
            scope: archive.scope.clone(),
            rows: archive.rows.clone(),
            bytes: Bytes::new(archive.bytes.clone()),
            incomplete: archive.incomplete,
        })
    }
}

impl TransmissionRecorder {
    pub(crate) fn reserve(
        authority: &ConnectionAuthority,
        limits: TransmissionLimits,
        private_token: &Bytes,
    ) -> Result<(Self, TransmissionObservationHandle), ProviderError> {
        authority.ensure_live()?;
        if limits.maximum_transmissions == 0
            || limits.maximum_transmissions > MAXIMUM_TRANSMISSIONS
            || limits.maximum_bytes == 0
            || limits.maximum_bytes > MAXIMUM_BYTES
        {
            return Err(exhausted("invalid transmission archive ceilings"));
        }
        let mut rows = Vec::new();
        rows.try_reserve_exact(limits.maximum_transmissions)
            .map_err(|_| exhausted("transmission metadata reservation"))?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(limits.maximum_bytes)
            .map_err(|_| exhausted("transmission byte reservation"))?;
        let archive = Arc::new(Mutex::new(Archive {
            scope: Scope {
                session: authority.session_id().clone(),
                incarnation: authority.incarnation_id().clone(),
                connection: authority.connection_id().clone(),
            },
            rows,
            bytes,
            maximum_transmissions: limits.maximum_transmissions,
            maximum_bytes: limits.maximum_bytes,
            reserved_bytes: 0,
            incomplete: false,
        }));
        Ok((
            Self {
                private_token: private_token.clone(),
                archive: archive.clone(),
            },
            TransmissionObservationHandle { archive },
        ))
    }

    pub(crate) fn begin(
        &self,
        authority: &ConnectionAuthority,
        request: &Envelope,
        identity: &HashRef,
        response_credit: usize,
    ) -> Result<TransmissionAttempt, ProviderError> {
        super::evidence::reject_private_envelope(request, self.private_token.as_slice())?;
        let request_bytes = encode(request)?;
        let mut archive = self
            .archive
            .lock()
            .map_err(|_| refused("transmission archive poisoned"))?;
        if archive.incomplete
            || archive.scope.session != *authority.session_id()
            || archive.scope.incarnation != *authority.incarnation_id()
            || archive.scope.connection != *authority.connection_id()
        {
            return Err(refused("transmission archive is unavailable or foreign"));
        }
        if request.request_hash(RequestOrigin::Controller)? != *identity {
            return Err(refused("transmission original identity differs"));
        }
        let request_id = request
            .request_id
            .0
            .clone()
            .ok_or(refused("transmission lacks original ID"))?;
        let credit = request_bytes
            .len()
            .checked_add(response_credit)
            .ok_or(exhausted("transmission credit overflow"))?;
        let next_credit = archive
            .reserved_bytes
            .checked_add(credit)
            .ok_or(exhausted("transmission lifetime credit overflow"))?;
        if archive.rows.len() == archive.maximum_transmissions
            || next_credit > archive.maximum_bytes
        {
            return Err(exhausted("transmission lifetime credit exhausted"));
        }
        let index = archive.rows.len();
        let start = archive.bytes.len();
        archive.bytes.extend_from_slice(&request_bytes);
        archive.rows.push(Row {
            transmission: U64::new((index + 1) as u64),
            origin: RequestOrigin::Controller,
            request_id,
            identity: identity.clone(),
            sent_sequence: request.sequence,
            write_completed: false,
            semantic_response_verified: false,
            request_start: start,
            request_length: request_bytes.len(),
            received: None,
        });
        archive.reserved_bytes = next_credit;
        Ok(TransmissionAttempt {
            private_token: self.private_token.clone(),
            archive: self.archive.clone(),
            index,
            response_credit,
            completed: false,
        })
    }
}

pub(crate) struct TransmissionAttempt {
    private_token: Bytes,
    archive: Arc<Mutex<Archive>>,
    index: usize,
    response_credit: usize,
    completed: bool,
}

impl TransmissionAttempt {
    pub(crate) fn sent(&mut self) -> Result<(), ProviderError> {
        let mut archive = self
            .archive
            .lock()
            .map_err(|_| refused("transmission archive poisoned"))?;
        archive.rows[self.index].write_completed = true;
        Ok(())
    }

    pub(crate) fn received(&mut self, envelope: &Envelope) -> Result<(), ProviderError> {
        super::evidence::reject_private_envelope(envelope, self.private_token.as_slice())?;
        let bytes = encode(envelope)?;
        let mut archive = self
            .archive
            .lock()
            .map_err(|_| refused("transmission archive poisoned"))?;
        if bytes.len() > self.response_credit || archive.rows[self.index].received.is_some() {
            archive.incomplete = true;
            return Err(exhausted("transmission response exceeds original credit"));
        }
        let start = archive.bytes.len();
        archive.bytes.extend_from_slice(&bytes);
        archive.rows[self.index].received = Some((start, bytes.len()));
        Ok(())
    }

    pub(crate) fn completed(&mut self) -> Result<(), ProviderError> {
        let mut archive = self
            .archive
            .lock()
            .map_err(|_| refused("transmission archive poisoned"))?;
        if !archive.rows[self.index].write_completed || archive.rows[self.index].received.is_none()
        {
            return Err(refused("transmission did not complete an actual send/read"));
        }
        archive.rows[self.index].semantic_response_verified = true;
        self.completed = true;
        Ok(())
    }
}

impl Drop for TransmissionAttempt {
    fn drop(&mut self) {
        if !self.completed {
            let mut archive = self
                .archive
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            archive.incomplete = true;
        }
    }
}

fn encode(envelope: &Envelope) -> Result<Vec<u8>, ProviderError> {
    let value =
        serde_json::to_value(envelope).map_err(crucible_node_contract::ContractError::from)?;
    Ok(canonical::canonical_json(&value)?)
}

fn refused(message: &'static str) -> ProviderError {
    ProviderError::Correlation(message)
}

fn exhausted(message: &'static str) -> ProviderError {
    ProviderError::ResourceExhausted(message)
}
