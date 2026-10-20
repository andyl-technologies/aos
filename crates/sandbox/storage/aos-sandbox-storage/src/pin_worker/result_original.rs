//! Owns partial fixed pin-result fields through the shared canonical decoder.
//!
//! This passive parser owns no service, effect, descriptor or fresh capability.
//! The selected physical stage pays its exact bounded representation before
//! constructing this owner; the ordinary adapter moves the same returned value
//! or error out at the original function boundary.

use super::*;

pub(crate) struct PinResultDecodeOriginalV1 {
    strings: [Option<String>; 5],
    dataset: Option<WorkspaceDatasetObservationV1>,
    root_attributes: Option<Result<PortableRootAttributesV1, crate::root_policy::WorkspaceRootPolicyError>>,
    proof: Option<WorkspaceRootPinProofV1>,
    proof_validation: Option<Result<(), crate::StorageStateError>>,
    pin: Option<WorkspacePinObservationV1>,
    output: Option<WorkspacePinWorkerResultV1>,
    canonical: Vec<u8>,
    canonical_encoding: Option<Result<(), ZfsWorkerError>>,
    result: Option<Result<(), ZfsWorkerError>>,
    entered: bool,
}

impl PinResultDecodeOriginalV1 {
    pub(crate) fn new() -> Self {
        Self { strings: std::array::from_fn(|_| None), dataset: None,
            root_attributes: None, proof: None, proof_validation: None,
            pin: None, output: None, canonical: Vec::new(),
            canonical_encoding: None, result: None, entered: false }
    }

    pub(crate) fn capture_once(&mut self, bytes: &[u8]) -> Result<(), ZfsWorkerError> {
        if self.entered {
            return Err(ZfsWorkerError::Protocol("pin result decoder is occupied"));
        }
        self.entered = true;
        self.result = Some(self.decode_inner(bytes));
        if matches!(self.result, Some(Ok(()))) { Ok(()) } else {
            Err(ZfsWorkerError::Protocol("pin result decoder original retained"))
        }
    }

    fn decode_inner(&mut self, bytes: &[u8]) -> Result<(), ZfsWorkerError> {
        if bytes.len() > MAXIMUM_PIN_WORKER_RESULT_BYTES {
            return Err(ZfsWorkerError::Protocol("workspace pin result exceeds byte ceiling"));
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.take(RESULT_MAGIC.len())? != RESULT_MAGIC {
            return Err(ZfsWorkerError::Protocol("workspace pin result header is invalid"));
        }
        if decoder.u16()? != WIRE_VERSION || decoder.u16()? != 0 {
            return Err(ZfsWorkerError::Protocol("workspace pin result header is invalid"));
        }
        let attempt_id = decoder.array()?;
        let observation_digest = ObjectDigest::from_bytes(decoder.array()?);
        self.dataset = Some(match decoder.byte()? {
            1 => {
                self.strings[0] = Some(decoder.result_string()?);
                let guid = decoder.u64()?;
                WorkspaceDatasetObservationV1::Exact { name: take_string(&mut self.strings[0]), guid }
            }
            2 => WorkspaceDatasetObservationV1::Absent,
            3 => WorkspaceDatasetObservationV1::Mismatch,
            _ => return Err(ZfsWorkerError::Protocol("workspace dataset result is invalid")),
        });
        self.pin = Some(match decoder.byte()? {
            1 => WorkspacePinObservationV1::Absent,
            2 => WorkspacePinObservationV1::Mismatch,
            3 => {
                let kernel_boot_id = decoder.array()?;
                let mount_namespace_device = decoder.u64()?;
                let mount_namespace_inode = decoder.u64()?;
                let mount_id = decoder.u64()?;
                for index in 1..5 {
                    self.strings[index] = Some(decoder.result_string()?);
                }
                let dataset_guid = decoder.u64()?;
                let root_device = decoder.u64()?;
                let root_inode = decoder.u64()?;
                if decoder.byte()? != 1 {
                    return Err(ZfsWorkerError::Protocol("workspace root attributes are invalid"));
                }
                self.root_attributes = Some(PortableRootAttributesV1::new(
                    decoder.u32()?, decoder.u32()?, u32::from(decoder.u16()?),
                ));
                let attributes = match self.root_attributes.as_ref() {
                    Some(Ok(attributes)) => *attributes,
                    _ => return Err(ZfsWorkerError::Protocol("workspace root attributes are invalid")),
                };
                self.proof_validation = Some(WorkspaceRootPinProofV1::capture_candidate_v1(
                    &mut self.proof, kernel_boot_id, mount_namespace_device,
                    mount_namespace_inode, mount_id,
                    take_string(&mut self.strings[1]), take_string(&mut self.strings[2]),
                    take_string(&mut self.strings[3]), take_string(&mut self.strings[4]),
                    dataset_guid, root_device, root_inode, attributes,
                ));
                if !matches!(self.proof_validation, Some(Ok(()))) {
                    return Err(ZfsWorkerError::Protocol("workspace pin proof is invalid"));
                }
                let Some(proof) = self.proof.take() else { std::process::abort() };
                WorkspacePinObservationV1::Present(proof)
            }
            _ => return Err(ZfsWorkerError::Protocol("workspace pin result is invalid")),
        });
        decoder.finish()?;
        let Some(dataset) = self.dataset.take() else { std::process::abort() };
        let Some(pin) = self.pin.take() else { std::process::abort() };
        self.output = Some(WorkspacePinWorkerResultV1::new(attempt_id, dataset, pin, observation_digest));
        let Some(output) = self.output.as_ref() else { std::process::abort() };
        self.canonical_encoding = Some(encode_result_into_v1(output, &mut self.canonical));
        if !matches!(self.canonical_encoding, Some(Ok(()))) {
            return Err(ZfsWorkerError::Protocol("pin result canonical encoding retained"));
        }
        if self.canonical != bytes {
            return Err(ZfsWorkerError::Protocol("workspace pin result is not canonical"));
        }
        Ok(())
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.root_attributes.as_ref().and_then(|result| result.as_ref().err())
            .map(|error| error as &(dyn std::error::Error + 'static))
            .or_else(|| self.proof_validation.as_ref()?.as_ref().err().map(|error| error as _))
            .or_else(|| self.canonical_encoding.as_ref()?.as_ref().err().map(|error| error as _))
            .or_else(|| self.result.as_ref()?.as_ref().err().map(|error| error as _))
    }

    pub(crate) fn output(&self) -> Option<&WorkspacePinWorkerResultV1> {
        matches!(self.result, Some(Ok(()))).then_some(())?;
        self.output.as_ref()
    }

    pub(crate) fn take_positive(&mut self) -> Option<WorkspacePinWorkerResultV1> {
        self.output()?;
        self.output.take()
    }

    pub(crate) fn into_ordinary_result_v1(mut self) -> Result<WorkspacePinWorkerResultV1, ZfsWorkerError> {
        if matches!(self.result, Some(Ok(()))) {
            return self.output.take().ok_or(ZfsWorkerError::Protocol("pin result output is absent"));
        }
        if let Some(Err(error)) = self.canonical_encoding.take() { return Err(error); }
        match self.result.take() {
            Some(Err(error)) => Err(error),
            _ => Err(ZfsWorkerError::Protocol("pin result decoder is incomplete")),
        }
    }

    pub(crate) fn requested_bytes_v1() -> Option<usize> {
        // Five exact protocol string limits cover the reached partial fields,
        // dataset or proof; they move between these slots and never clone.
        // Canonical output starts at256 and grows geometrically before the old
        // late16KiB check; include old+new reallocations and its final frame.
        std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(5 * MAXIMUM_RESULT_STRING_BYTES)?
            .checked_add(3 * (MAXIMUM_PIN_WORKER_RESULT_BYTES + 256))?
            .checked_add(std::mem::size_of::<Decoder<'static>>())?
            .checked_add(8 * 256)
    }

}

fn take_string(slot: &mut Option<String>) -> String {
    match slot.take() { Some(value) => value, None => std::process::abort() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncated_guid_keeps_the_actual_decoded_dataset_string() {
        let result = WorkspacePinWorkerResultV1::new([1; 16],
            WorkspaceDatasetObservationV1::Exact { name: "tank/aos/work".to_owned(), guid: 7 },
            WorkspacePinObservationV1::Absent, ObjectDigest::from_bytes([2; 32]));
        let mut bytes = encode_result(&result).unwrap();
        // Preserve the native wire's dataset name and remove the subsequent
        // GUID/pin suffix, reaching a refusal after that actual allocation.
        bytes.truncate(60 + 1 + 2 + "tank/aos/work".len() + 2);
        let mut original = PinResultDecodeOriginalV1::new();

        assert!(original.capture_once(&bytes).is_err());
        assert_eq!(original.strings[0].as_deref(), Some("tank/aos/work"));
        assert!(original.dataset.is_none());
        assert!(original.take_positive().is_none());
        let before = original.failure().unwrap() as *const dyn std::error::Error as *const ();
        assert!(original.capture_once(&bytes).is_err());
        assert_eq!(before, original.failure().unwrap() as *const dyn std::error::Error as *const ());
        assert!(decode_result(&bytes).is_err());
    }

    #[test]
    fn rejected_completed_proof_and_its_strings_stay_owned() {
        let proof = WorkspaceRootPinProofV1::new([3; 16], 4, 5, 6, "/".to_owned(),
            "/run/aos/pin-fixture".to_owned(), "zfs".to_owned(), "tank/aos/work".to_owned(),
            7, 8, 9, PortableRootAttributesV1::new(0, 0, 0o755).unwrap()).unwrap();
        let result = WorkspacePinWorkerResultV1::new([1; 16], WorkspaceDatasetObservationV1::Absent,
            WorkspacePinObservationV1::Present(proof), ObjectDigest::from_bytes([2; 32]));
        let mut bytes = encode_result(&result).unwrap();
        bytes[62..78].fill(0);
        let mut original = PinResultDecodeOriginalV1::new();

        assert!(original.capture_once(&bytes).is_err());
        let proof = original.proof.as_ref().unwrap();
        assert_eq!(proof.kernel_boot_id(), [0; 16]);
        assert_eq!(proof.mount_point(), "/run/aos/pin-fixture");
        assert_eq!(proof.superblock_source(), "tank/aos/work");
        assert!(matches!(original.proof_validation, Some(Err(_))));
        assert!(original.take_positive().is_none());
        assert!(decode_result(&bytes).is_err());
    }

    #[test]
    fn late_canonical_refusal_keeps_the_completed_dto() {
        let result = WorkspacePinWorkerResultV1::new([1; 16], WorkspaceDatasetObservationV1::Absent,
            WorkspacePinObservationV1::Absent, ObjectDigest::from_bytes([2; 32]));
        let mut bytes = encode_result(&result).unwrap();
        bytes[12..28].fill(0);
        let mut original = PinResultDecodeOriginalV1::new();

        assert!(original.capture_once(&bytes).is_err());
        assert_eq!(original.output.as_ref().unwrap().attempt_id(), [0; 16]);
        assert!(matches!(original.canonical_encoding, Some(Err(_))));
        assert!(original.failure().is_some());
        assert!(original.take_positive().is_none());
        assert!(decode_result(&bytes).is_err());
    }
}
