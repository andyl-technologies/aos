//! Pre-effect reservations and sealed capture of authenticated boundary responses.

use std::{collections::BTreeMap, rc::Rc};

use crucible_node_contract::{ContentRef, Position, U64, canonical};

use super::{codec::TranscriptError, types::*};

/// Owns complete recorded source data after every original reservation closed.
///
/// Only the live recording adapter can create this seal. In particular, decoding
/// public JSON and recomputing its content reference cannot authenticate a source.
pub struct CapturedTranscript {
    pub(super) data: BoundaryTranscript,
    pub(super) bytes: Vec<u8>,
    pub(super) reference: ContentRef,
}

impl CapturedTranscript {
    /// Borrows the complete original source, raw bytes and physical uncertainty.
    pub fn transcript(&self) -> &BoundaryTranscript {
        &self.data
    }

    /// Borrows the exact canonical recorded envelope.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Borrows the content identity; it is distinct from source authentication.
    pub fn reference(&self) -> &ContentRef {
        &self.reference
    }
}

pub(super) struct Reservation {
    authority: Rc<()>,
    number: u64,
}

pub(super) struct CaptureSession {
    data: BoundaryTranscript,
    authority: Rc<()>,
    next_reservation: u64,
    outstanding: BTreeMap<u64, ()>,
    reserved_bytes: u64,
    invalid: bool,
}

impl CaptureSession {
    pub(super) fn new(
        origin: TranscriptOrigin,
        limits: TranscriptLimits,
    ) -> Result<Self, TranscriptError> {
        Self::new_selected(origin, limits, false)
    }

    pub(super) fn new_selected(
        origin: TranscriptOrigin,
        limits: TranscriptLimits,
        byte_strings: bool,
    ) -> Result<Self, TranscriptError> {
        let data = BoundaryTranscript {
            schema_version: if byte_strings { 2 } else { 1 },
            origin,
            limits,
            records: Vec::new(),
        };
        let reserved_bytes = data.canonical_bytes()?.len() as u64;
        Ok(Self {
            data,
            authority: Rc::new(()),
            next_reservation: 0,
            outstanding: BTreeMap::new(),
            reserved_bytes,
            invalid: false,
        })
    }

    pub(super) fn context(&self) -> Result<ContentRef, TranscriptError> {
        super::codec::context_commitment(&self.data.origin)
    }

    pub(super) fn request_bytes(
        &self,
        request: &TranscriptRequest,
    ) -> Result<Vec<u8>, TranscriptError> {
        if self.data.schema_version == 2 {
            super::byte_wire::request(request, self.maximum_record_bytes())
        } else {
            super::codec::encode(request)
        }
    }

    pub(super) fn maximum_record_bytes(&self) -> u64 {
        self.data.limits.maximum_record_bytes.get()
    }

    // The entire worst-case response is charged before native dispatch. A failed
    // request cannot free this identity for a replacement physical execution.
    pub(super) fn reserve(&mut self) -> Result<Reservation, TranscriptError> {
        if self.invalid {
            return Err(TranscriptError::Unqualified(
                "capture already failed".into(),
            ));
        }
        let records = self
            .data
            .records
            .len()
            .checked_add(self.outstanding.len())
            .ok_or(TranscriptError::CaptureLimit)?;
        let bytes = self
            .reserved_bytes
            .checked_add(self.data.limits.maximum_record_bytes.get())
            // Reserve the array separator before any corresponding native effect.
            // Charging one for the first record is a conservative extra byte.
            .and_then(|bytes| bytes.checked_add(1))
            .ok_or(TranscriptError::CaptureLimit)?;
        if records as u64 >= self.data.limits.maximum_records.get()
            || bytes > self.data.limits.maximum_total_bytes.get()
        {
            self.invalid = true;
            return Err(TranscriptError::CaptureLimit);
        }
        let number = self.next_reservation;
        self.next_reservation = number.checked_add(1).ok_or(TranscriptError::CaptureLimit)?;
        self.outstanding.insert(number, ());
        self.reserved_bytes = bytes;
        Ok(Reservation {
            authority: self.authority.clone(),
            number,
        })
    }

    pub(super) fn retain(
        &mut self,
        reservation: Reservation,
        request: TranscriptRequest,
        response_bytes: Vec<u8>,
        evidence: Vec<crate::node_scheduling::InputPayload>,
        assigned_positions: Vec<Position>,
        physical_uncertainty: PhysicalTimingUncertainty,
    ) -> Result<(), TranscriptError> {
        if self.invalid
            || !Rc::ptr_eq(&reservation.authority, &self.authority)
            || !self.outstanding.contains_key(&reservation.number)
        {
            return Err(TranscriptError::Unqualified(
                "original capture reservation absent".into(),
            ));
        }
        let response = canonical::content_ref(&response_bytes, "application/json")
            .map_err(super::codec::invalid)?;
        let record = TranscriptRecord {
            sequence: U64::new(self.data.records.len() as u64),
            request,
            response,
            response_bytes,
            evidence,
            assigned_positions,
            physical_uncertainty,
        };
        let bytes = super::codec::record_bytes(
            &record,
            self.data.schema_version,
            self.maximum_record_bytes(),
        )?;
        if bytes.len() as u64 > self.data.limits.maximum_record_bytes.get() {
            self.invalid = true;
            return Err(TranscriptError::CaptureLimit);
        }
        self.data.records.push(record);
        if let Err(error) = self.data.validate_integrity() {
            self.invalid = true;
            return Err(error);
        }
        self.outstanding.remove(&reservation.number);
        self.reserved_bytes = self
            .reserved_bytes
            .checked_sub(self.data.limits.maximum_record_bytes.get())
            .and_then(|value| value.checked_sub(1))
            .and_then(|value| value.checked_add(bytes.len() as u64 + 1))
            .ok_or(TranscriptError::CaptureLimit)?;
        Ok(())
    }

    pub(super) fn invalidate(&mut self) {
        self.invalid = true;
    }

    pub(super) fn release_no_effect(
        &mut self,
        reservation: Reservation,
    ) -> Result<(), TranscriptError> {
        if !Rc::ptr_eq(&reservation.authority, &self.authority)
            || self.outstanding.remove(&reservation.number).is_none()
        {
            self.invalid = true;
            return Err(TranscriptError::Unqualified(
                "foreign completion reservation".into(),
            ));
        }
        self.reserved_bytes = self
            .reserved_bytes
            .checked_sub(self.data.limits.maximum_record_bytes.get())
            .and_then(|value| value.checked_sub(1))
            .ok_or(TranscriptError::CaptureLimit)?;
        Ok(())
    }

    pub(super) fn finish(self) -> Result<CapturedTranscript, TranscriptError> {
        if self.invalid || !self.outstanding.is_empty() || self.data.records.is_empty() {
            return Err(TranscriptError::Unqualified(
                "capture failed or has outstanding original interactions".into(),
            ));
        }
        let bytes = self.data.canonical_bytes()?;
        let reference =
            canonical::content_ref(&bytes, "application/vnd.crucible.boundary-transcript+json")
                .map_err(super::codec::invalid)?;
        Ok(CapturedTranscript {
            data: self.data,
            bytes,
            reference,
        })
    }
}
