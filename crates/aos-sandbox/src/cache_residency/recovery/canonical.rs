//! Canonical bounded primitive encoding shared by durable cache formats.

use super::*;

pub(super) fn canonical_payload_digest(
    payload: &CacheAtomicObjectPayloadV1,
    limits: CacheRecoveryLimitsV1,
) -> Result<ObjectDigest, RecoveryError> {
    Ok(payload_digest_bytes(&encode_atomic_payload_components(
        payload, limits,
    )?))
}

pub(super) fn payload_digest_bytes(bytes: &[u8]) -> ObjectDigest {
    digest_bytes(b"aos.sandbox.cache.atomic-payload-bytes.v1\0", bytes)
}

pub(super) fn digest_bytes(domain: &[u8], bytes: &[u8]) -> ObjectDigest {
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest as _;
    hasher.update(domain);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    ObjectDigest::from_bytes(hasher.finalize().into())
}

pub(super) struct CanonicalWriter {
    bytes: Vec<u8>,
    maximum_bytes: usize,
}

impl CanonicalWriter {
    pub(super) fn new(magic: &[u8; 8], maximum_bytes: usize) -> Result<Self, RecoveryError> {
        if maximum_bytes < 16 || maximum_bytes > MAXIMUM_COMPONENT_BYTES {
            return Err(RecoveryError::Capacity);
        }
        let mut writer = Self {
            bytes: Vec::with_capacity(256.min(maximum_bytes)),
            maximum_bytes,
        };
        writer.bytes(magic)?;
        writer.u16(CODEC_VERSION)?;
        writer.bytes(&[0; 6])?;
        Ok(writer)
    }

    pub(super) fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(super) fn finish(self) -> Vec<u8> {
        self.bytes
    }

    pub(super) fn bytes(&mut self, value: &[u8]) -> Result<(), RecoveryError> {
        let length = self
            .bytes
            .len()
            .checked_add(value.len())
            .ok_or(RecoveryError::Capacity)?;
        if length > self.maximum_bytes {
            return Err(RecoveryError::Capacity);
        }
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    pub(super) fn u8(&mut self, value: u8) -> Result<(), RecoveryError> {
        self.bytes(&[value])
    }

    pub(super) fn u16(&mut self, value: u16) -> Result<(), RecoveryError> {
        self.bytes(&value.to_be_bytes())
    }

    pub(super) fn u32(&mut self, value: usize) -> Result<(), RecoveryError> {
        let value = u32::try_from(value).map_err(|_| RecoveryError::Capacity)?;
        self.bytes(&value.to_be_bytes())
    }

    pub(super) fn u64(&mut self, value: u64) -> Result<(), RecoveryError> {
        self.bytes(&value.to_be_bytes())
    }

    pub(super) fn identity(&mut self, value: &[u8; 16]) -> Result<(), RecoveryError> {
        self.bytes(value)
    }

    pub(super) fn digest(&mut self, value: ObjectDigest) -> Result<(), RecoveryError> {
        self.bytes(value.as_bytes())
    }

    pub(super) fn optional_identity(
        &mut self,
        value: Option<[u8; 16]>,
    ) -> Result<(), RecoveryError> {
        match value {
            Some(value) => {
                self.u8(1)?;
                self.bytes(&value)
            }
            None => {
                self.u8(0)?;
                self.bytes(&[0; 16])
            }
        }
    }

    pub(super) fn optional_digest(
        &mut self,
        value: Option<ObjectDigest>,
    ) -> Result<(), RecoveryError> {
        match value {
            Some(value) => {
                self.u8(1)?;
                self.digest(value)
            }
            None => {
                self.u8(0)?;
                self.digest(ObjectDigest::from_bytes([0; 32]))
            }
        }
    }

    pub(super) fn length_prefixed(&mut self, value: &[u8]) -> Result<(), RecoveryError> {
        self.u32(value.len())?;
        self.bytes(value)
    }
}

pub(super) struct CanonicalReader<'bytes> {
    bytes: &'bytes [u8],
    position: usize,
}

impl<'bytes> CanonicalReader<'bytes> {
    pub(super) fn new(
        magic: &[u8; 8],
        bytes: &'bytes [u8],
        maximum_bytes: usize,
    ) -> Result<Self, RecoveryError> {
        if bytes.len() < 16
            || bytes.len() > maximum_bytes
            || maximum_bytes > MAXIMUM_COMPONENT_BYTES
        {
            return Err(RecoveryError::MalformedPayload);
        }
        let version = CODEC_VERSION.to_be_bytes();
        if &bytes[0..8] != magic || bytes[8..10] != version || bytes[10..16] != [0; 6] {
            return Err(RecoveryError::MalformedPayload);
        }
        Ok(Self {
            bytes,
            position: 16,
        })
    }

    pub(super) fn position(&self) -> usize {
        self.position
    }

    pub(super) fn complete(&self) -> Result<(), RecoveryError> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(RecoveryError::MalformedPayload)
        }
    }

    pub(super) fn take(&mut self, length: usize) -> Result<&'bytes [u8], RecoveryError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(RecoveryError::MalformedPayload)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(RecoveryError::MalformedPayload)?;
        self.position = end;
        Ok(value)
    }

    pub(super) fn array<const N: usize>(&mut self) -> Result<[u8; N], RecoveryError> {
        self.take(N)?
            .try_into()
            .map_err(|_| RecoveryError::MalformedPayload)
    }

    pub(super) fn identity(&mut self) -> Result<[u8; 16], RecoveryError> {
        self.array()
    }

    pub(super) fn digest(&mut self) -> Result<ObjectDigest, RecoveryError> {
        Ok(ObjectDigest::from_bytes(self.array()?))
    }

    pub(super) fn expect_digest(&mut self, expected: ObjectDigest) -> Result<(), RecoveryError> {
        if self.digest()? == expected {
            Ok(())
        } else {
            Err(RecoveryError::PayloadMismatch)
        }
    }

    pub(super) fn u8(&mut self) -> Result<u8, RecoveryError> {
        Ok(self.array::<1>()?[0])
    }

    pub(super) fn u16(&mut self) -> Result<u16, RecoveryError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    pub(super) fn u32(&mut self) -> Result<u32, RecoveryError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    pub(super) fn u64(&mut self) -> Result<u64, RecoveryError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    pub(super) fn count(&mut self, maximum: usize) -> Result<usize, RecoveryError> {
        let count = usize::try_from(self.u32()?).map_err(|_| RecoveryError::Capacity)?;
        if count > maximum {
            return Err(RecoveryError::Capacity);
        }
        Ok(count)
    }

    pub(super) fn boolean(&mut self) -> Result<bool, RecoveryError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(RecoveryError::MalformedPayload),
        }
    }

    pub(super) fn optional_identity(&mut self) -> Result<Option<[u8; 16]>, RecoveryError> {
        let present = self.boolean()?;
        let value = self.identity()?;
        match (present, value == [0; 16]) {
            (false, true) => Ok(None),
            (true, false) => Ok(Some(value)),
            _ => Err(RecoveryError::MalformedPayload),
        }
    }

    pub(super) fn optional_digest(&mut self) -> Result<Option<ObjectDigest>, RecoveryError> {
        let present = self.boolean()?;
        let value = self.digest()?;
        match (present, value.as_bytes() == &[0; 32]) {
            (false, true) => Ok(None),
            (true, false) => Ok(Some(value)),
            _ => Err(RecoveryError::MalformedPayload),
        }
    }

    pub(super) fn length_prefixed(
        &mut self,
        maximum: usize,
    ) -> Result<&'bytes [u8], RecoveryError> {
        let length = usize::try_from(self.u32()?).map_err(|_| RecoveryError::Capacity)?;
        if length > maximum {
            return Err(RecoveryError::Capacity);
        }
        self.take(length)
    }
}

pub(super) fn write_descriptor(
    writer: &mut CanonicalWriter,
    descriptor: &ObjectDescriptor,
) -> Result<(), RecoveryError> {
    let media = descriptor.media_type().as_str().as_bytes();
    let length = u16::try_from(media.len()).map_err(|_| RecoveryError::PayloadMismatch)?;
    writer.u16(length)?;
    writer.bytes(media)?;
    writer.digest(descriptor.digest())?;
    writer.u64(descriptor.encoded_size())
}

pub(super) fn read_descriptor(
    reader: &mut CanonicalReader<'_>,
) -> Result<ObjectDescriptor, RecoveryError> {
    let media_length = usize::from(reader.u16()?);
    let media = std::str::from_utf8(reader.take(media_length)?)
        .map_err(|_| RecoveryError::MalformedPayload)?;
    let media = MediaType::new(media).map_err(|_| RecoveryError::MalformedPayload)?;
    let descriptor = ObjectDescriptor::new(media, reader.digest()?, reader.u64()?);
    super::super::domain::validate_object_descriptor(&descriptor)
        .map_err(|_| RecoveryError::PayloadMismatch)?;
    Ok(descriptor)
}

pub(super) fn write_seal(
    writer: &mut CanonicalWriter,
    seal: super::super::catalog::ImmutableSealV1,
) -> Result<(), RecoveryError> {
    writer.u8(seal.profile as u8)?;
    writer.digest(seal.measurement)
}

pub(super) fn read_seal(
    reader: &mut CanonicalReader<'_>,
) -> Result<super::super::catalog::ImmutableSealV1, RecoveryError> {
    let profile = match reader.u8()? {
        1 => super::super::catalog::SealProfileV1::FsVeritySha256,
        2 => super::super::catalog::SealProfileV1::ReadOnlyZfsSnapshot,
        _ => return Err(RecoveryError::MalformedPayload),
    };
    super::super::catalog::ImmutableSealV1 {
        profile,
        measurement: reader.digest()?,
    }
    .validate()
    .map_err(|_| RecoveryError::PayloadMismatch)
}

pub(super) fn write_eviction_candidate(
    writer: &mut CanonicalWriter,
    candidate: &EvictionCandidateV1,
) -> Result<(), RecoveryError> {
    write_descriptor(writer, &candidate.descriptor)?;
    writer.digest(candidate.catalog_digest)?;
    writer.bytes(candidate.backing.as_bytes())?;
    writer.digest(candidate.root_custody)?;
    writer.digest(candidate.canonical_name)?;
    writer.u64(candidate.physical_bytes)?;
    writer.u8(candidate.original_presence as u8)?;
    writer.u64(candidate.last_use_generation)?;
    writer.bytes(&candidate.pressure_class.to_be_bytes())
}

pub(super) fn read_eviction_candidate(
    reader: &mut CanonicalReader<'_>,
) -> Result<EvictionCandidateV1, RecoveryError> {
    Ok(EvictionCandidateV1 {
        descriptor: read_descriptor(reader)?,
        catalog_digest: reader.digest()?,
        backing: super::super::catalog::BackingObjectIdentityV1::from_bytes(reader.array()?)
            .map_err(|_| RecoveryError::MalformedPayload)?,
        root_custody: reader.digest()?,
        canonical_name: reader.digest()?,
        physical_bytes: reader.u64()?,
        original_presence: catalog_presence(reader.u8()?)?,
        last_use_generation: reader.u64()?,
        pressure_class: u32::from_be_bytes(reader.array()?),
    })
}

pub(super) fn reservation_state(code: u8) -> Result<ReservationStateV1, RecoveryError> {
    match code {
        1 => Ok(ReservationStateV1::Reserved),
        2 => Ok(ReservationStateV1::Uncertain),
        3 => Ok(ReservationStateV1::Converted),
        4 => Ok(ReservationStateV1::Released),
        5 => Ok(ReservationStateV1::Evicted),
        _ => Err(RecoveryError::MalformedPayload),
    }
}

pub(super) fn catalog_presence(code: u8) -> Result<CatalogPresenceV1, RecoveryError> {
    match code {
        1 => Ok(CatalogPresenceV1::Committed),
        2 => Ok(CatalogPresenceV1::Deleting),
        3 => Ok(CatalogPresenceV1::Quarantined),
        4 => Ok(CatalogPresenceV1::Evicted),
        _ => Err(RecoveryError::MalformedPayload),
    }
}

pub(super) fn pin_kind(code: u8) -> Result<CachePinKindV1, RecoveryError> {
    match code {
        1 => Ok(CachePinKindV1::LogicalLease),
        2 => Ok(CachePinKindV1::SourceRetention),
        3 => Ok(CachePinKindV1::KernelReference),
        4 => Ok(CachePinKindV1::BackingRegistration),
        _ => Err(RecoveryError::MalformedPayload),
    }
}

pub(super) fn pin_drain_outcome(code: u8) -> Result<PinDrainOutcomeV1, RecoveryError> {
    match code {
        1 => Ok(PinDrainOutcomeV1::NeverInstalled),
        2 => Ok(PinDrainOutcomeV1::ConsumerAbsentAndReferencesClosed),
        _ => Err(RecoveryError::MalformedPayload),
    }
}

pub(super) fn admission_stage(code: u8) -> Result<AdmissionStageV1, RecoveryError> {
    match code {
        1 => Ok(AdmissionStageV1::Reserved),
        2 => Ok(AdmissionStageV1::PrivateDestinationCreated),
        3 => Ok(AdmissionStageV1::ContentTransferred),
        4 => Ok(AdmissionStageV1::ContentVerified),
        5 => Ok(AdmissionStageV1::WritersClosed),
        6 => Ok(AdmissionStageV1::SealEnabledAndVerified),
        7 => Ok(AdmissionStageV1::InodeSynced),
        8 => Ok(AdmissionStageV1::CanonicalNamePublished),
        9 => Ok(AdmissionStageV1::ParentSynced),
        10 => Ok(AdmissionStageV1::CatalogCommitted),
        11 => Ok(AdmissionStageV1::Uncertain),
        12 => Ok(AdmissionStageV1::Quarantined),
        13 => Ok(AdmissionStageV1::Aborted),
        _ => Err(RecoveryError::MalformedPayload),
    }
}

pub(super) fn eviction_state(code: u8) -> Result<EvictionCandidateStateV1, RecoveryError> {
    match code {
        1 => Ok(EvictionCandidateStateV1::Selected),
        2 => Ok(EvictionCandidateStateV1::RestoredBeforeEffect),
        3 => Ok(EvictionCandidateStateV1::Deleting),
        4 => Ok(EvictionCandidateStateV1::UnlinkAmbiguous),
        5 => Ok(EvictionCandidateStateV1::RemovedAwaitingReclaim),
        6 => Ok(EvictionCandidateStateV1::Reclaimed),
        7 => Ok(EvictionCandidateStateV1::RestoredAfterRename),
        8 => Ok(EvictionCandidateStateV1::Quarantined),
        _ => Err(RecoveryError::MalformedPayload),
    }
}

pub(super) fn record_kind(code: u8) -> Result<CacheRecordKindV1, RecoveryError> {
    match code {
        1 => Ok(CacheRecordKindV1::Domain),
        2 => Ok(CacheRecordKindV1::Quota),
        3 => Ok(CacheRecordKindV1::Reservation),
        4 => Ok(CacheRecordKindV1::Admission),
        5 => Ok(CacheRecordKindV1::Catalog),
        6 => Ok(CacheRecordKindV1::Pin),
        7 => Ok(CacheRecordKindV1::EvictionPlan),
        8 => Ok(CacheRecordKindV1::EvictionProgress),
        9 => Ok(CacheRecordKindV1::Scrub),
        10 => Ok(CacheRecordKindV1::ReadHandoff),
        11 => Ok(CacheRecordKindV1::LookupMemo),
        12 => Ok(CacheRecordKindV1::Poison),
        13 => Ok(CacheRecordKindV1::Compaction),
        _ => Err(RecoveryError::MalformedPayload),
    }
}
