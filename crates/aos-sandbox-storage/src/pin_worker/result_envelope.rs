//! Shares the two existing repair-result envelopes and partial pin decoder.
//!
//! Each protocol supplies its existing header, version, record cursor and
//! canonical writer. The generic owner is representation only and has no
//! effect, service, writer, funding or fresh-observation constructor.

use super::{PinResultDecodeOriginalV1, WorkspacePinWorkerResultV1};
use crate::worker_wire::{DecodeErrors, Decoder};
use crate::ZfsWorkerError;
use aos_sandbox_core::ObjectDigest;

pub(crate) trait PinResultEnvelopeV1: Sized {
    const MAGIC: &'static [u8; 8];
    const VERSION: u16;
    const ERRORS: &'static DecodeErrors;
    const CEILING_ERROR: &'static str;
    const HEADER_ERROR: &'static str;
    const CANONICAL_ERROR: &'static str;

    fn observation_bytes<'a>(decoder: &mut Decoder<'a>) -> Result<&'a [u8], ZfsWorkerError>;
    fn from_parts(digest: ObjectDigest, observation: WorkspacePinWorkerResultV1) -> Self;
    fn encode_into(&self, outer: &mut Vec<u8>, nested: &mut Vec<u8>) -> Result<(), ZfsWorkerError>;
}

pub(crate) struct PinResultEnvelopeOriginalV1<T> {
    nested: PinResultDecodeOriginalV1,
    nested_result: Option<Result<(), ZfsWorkerError>>,
    output: Option<T>,
    canonical: Vec<u8>,
    canonical_nested: Vec<u8>,
    encoding: Option<Result<(), ZfsWorkerError>>,
    result: Option<Result<(), ZfsWorkerError>>,
    entered: bool,
}

impl<T: PinResultEnvelopeV1> PinResultEnvelopeOriginalV1<T> {
    pub(crate) fn new() -> Self {
        Self {
            nested: PinResultDecodeOriginalV1::new(), nested_result: None,
            output: None, canonical: Vec::new(), canonical_nested: Vec::new(),
            encoding: None, result: None, entered: false,
        }
    }

    pub(crate) fn capture_once(&mut self, bytes: &[u8]) -> Result<(), ZfsWorkerError> {
        if self.entered { return Err(marker()); }
        self.entered = true;
        self.result = Some(self.decode_inner(bytes));
        if matches!(self.result, Some(Ok(()))) { Ok(()) } else { Err(marker()) }
    }

    fn decode_inner(&mut self, bytes: &[u8]) -> Result<(), ZfsWorkerError> {
        if bytes.len() > super::MAXIMUM_PIN_WORKER_RESULT_BYTES {
            return Err(ZfsWorkerError::Protocol(T::CEILING_ERROR));
        }
        let mut decoder = Decoder::new(bytes, T::ERRORS);
        if decoder.take(T::MAGIC.len())? != T::MAGIC
            || decoder.u16()? != T::VERSION
            || decoder.u16()? != 0
        {
            return Err(ZfsWorkerError::Protocol(T::HEADER_ERROR));
        }
        let digest = ObjectDigest::from_bytes(decoder.array()?);
        self.nested_result = Some(self.nested.capture_once(T::observation_bytes(&mut decoder)?));
        if !matches!(self.nested_result, Some(Ok(()))) { return Err(marker()); }
        decoder.finish()?;
        let Some(observation) = self.nested.take_positive() else { std::process::abort() };
        self.output = Some(T::from_parts(digest, observation));
        let Some(output) = self.output.as_ref() else { std::process::abort() };
        self.encoding = Some(output.encode_into(&mut self.canonical, &mut self.canonical_nested));
        if !matches!(self.encoding, Some(Ok(()))) { return Err(marker()); }
        if self.canonical != bytes { return Err(ZfsWorkerError::Protocol(T::CANONICAL_ERROR)); }
        Ok(())
    }

    pub(crate) fn output(&self) -> Option<&T> {
        if !matches!(self.result, Some(Ok(()))) { return None; }
        self.output.as_ref()
    }

    pub(crate) fn take_positive(&mut self) -> Option<T> {
        self.output()?;
        self.output.take()
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.nested.failure()
            .or_else(|| self.encoding.as_ref()?.as_ref().err().map(|error| error as _))
            .or_else(|| self.result.as_ref()?.as_ref().err().map(|error| error as _))
    }

    pub(crate) fn into_ordinary_result_v1(mut self) -> Result<T, ZfsWorkerError> {
        if let Some(output) = self.take_positive() { return Ok(output); }
        if matches!(self.nested_result, Some(Err(_))) {
            return match self.nested.into_ordinary_result_v1() {
                Err(error) => Err(error),
                Ok(_) => Err(marker()),
            };
        }
        if let Some(Err(error)) = self.encoding { return Err(error); }
        match self.result { Some(Err(error)) => Err(error), _ => Err(marker()) }
    }

    pub(crate) fn requested_bytes_v1() -> Option<usize> {
        // Both additional canonical writers can hold old+new reallocations;
        // the SAME partial pin decoder owns its own canonical and five strings.
        std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(PinResultDecodeOriginalV1::requested_bytes_v1()?)?
            .checked_add(6 * (super::MAXIMUM_PIN_WORKER_RESULT_BYTES + 256))?
            .checked_add(std::mem::size_of::<Decoder<'static>>())?
            .checked_add(4 * 256)
    }

}

fn marker() -> ZfsWorkerError {
    ZfsWorkerError::Protocol("repair result envelope original retained")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace_pin::{WorkspaceDatasetObservationV1, WorkspacePinObservationV1};
    use crate::workspace_repair_observer::WorkspacePinRepairObserverResultV1;

    fn encoded_envelope(digest: [u8; 32]) -> Vec<u8> {
        let observation = WorkspacePinWorkerResultV1::new(
            [1; 16], WorkspaceDatasetObservationV1::Absent,
            WorkspacePinObservationV1::Absent, ObjectDigest::from_bytes([2; 32]),
        );
        let nested = crate::pin_worker::encode_result(&observation).unwrap();
        let mut bytes = b"AOSZRPR1".to_vec();
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.extend_from_slice(&0_u16.to_be_bytes());
        bytes.extend_from_slice(&digest);
        bytes.extend_from_slice(&(nested.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&nested);
        bytes
    }

    #[test]
    fn trailing_outer_error_keeps_the_actual_positive_nested_model() {
        let mut bytes = encoded_envelope([3; 32]);
        bytes.push(9);
        let mut original = PinResultEnvelopeOriginalV1::<WorkspacePinRepairObserverResultV1>::new();

        assert!(original.capture_once(&bytes).is_err());
        let nested = original.nested.output().unwrap();
        assert_eq!(nested.attempt_id(), [1; 16]);
        assert!(original.output.is_none());
        let first = original.failure().unwrap() as *const dyn std::error::Error as *const ();

        assert!(original.capture_once(&encoded_envelope([4; 32])).is_err());
        assert_eq!(first, original.failure().unwrap() as *const dyn std::error::Error as *const ());
        assert_eq!(original.nested.output().unwrap().attempt_id(), [1; 16]);
    }

    #[test]
    fn invalid_probe_keeps_the_completed_outer_dto_before_canonical_refusal() {
        let bytes = encoded_envelope([0; 32]);
        let mut original = PinResultEnvelopeOriginalV1::<WorkspacePinRepairObserverResultV1>::new();

        assert!(original.capture_once(&bytes).is_err());
        let output = original.output.as_ref().unwrap();
        assert_eq!(output.probe_digest(), ObjectDigest::from_bytes([0; 32]));
        assert_eq!(output.observation().attempt_id(), [1; 16]);
        assert!(original.canonical.is_empty());
        assert!(matches!(original.encoding, Some(Err(_))));
    }
}
