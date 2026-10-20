//! Captures actual atomic program and authenticated record encoding buffers.
//!
//! Ordinary and selected callers share the existing wire recipe. The selected
//! State guard pays reached lengths before either real encoder allocation.

use super::*;

#[derive(Clone, Copy)]
enum Failure {
    Geometry,
    Payment,
    Version,
    Program,
    ProgramLength,
    Mac,
}

pub(super) struct AtomicEncodingOriginalV1 {
    encoded: Option<Vec<u8>>,
    mac: Option<Result<HmacSha256, StorageStateError>>,
    program_length: Option<Result<u32, StorageStateError>>,
    program: Option<Result<Vec<u8>, StorageStateError>>,
    program_encoding: crate::lifecycle_atomic_snapshot::AtomicProgramEncodingOriginalV1,
    version: Option<Result<u16, StorageStateError>>,
    payment: Option<Result<(), aos_sandbox::StorageReceivingClosedV1>>,
    geometry: Option<Result<usize, aos_sandbox_core::AccountingError>>,
    first: Option<Failure>,
    entered: bool,
}

impl AtomicEncodingOriginalV1 {
    pub(super) const fn new() -> Self {
        Self {
            encoded: None,
            mac: None,
            program_length: None,
            program: None,
            program_encoding: crate::lifecycle_atomic_snapshot::AtomicProgramEncodingOriginalV1::new(),
            version: None,
            payment: None,
            geometry: None,
            first: None,
            entered: false,
        }
    }

    pub(super) fn encode(
        &mut self,
        record: &AtomicDatasetSnapshotRecordV1,
        key: &StorageStateKey,
        receiving: Option<&mut super::encoding::StateEncodingLoanV1<'_, '_>>,
    ) -> Result<Vec<u8>, StorageStateError> {
        if self.entered {
            return Err(StorageStateError::Receiving);
        }
        self.entered = true;
        let selected = receiving.is_some();
        self.first = Some(Failure::Version);
        self.version = Some(if record.post_head.is_some() {
            if record.phase != AtomicDatasetSnapshotPhaseV1::Committed
                || record.observation.is_none()
                || record.post_head.is_some_and(|head| {
                    record.program.format_version() != 2
                        || record.program.catalog_generation().checked_add(1)
                            != Some(head.generation())
                        || record.program.catalog_head() == head.digest()
                })
            {
                Err(StorageStateError::InvalidValue)
            } else {
                Ok(ATOMIC_SNAPSHOT_VERSION_V3)
            }
        } else {
            Ok(ATOMIC_SNAPSHOT_VERSION_V2)
        });
        let Some(version) = self.version.as_ref()
            .and_then(|result| result.as_ref().ok()).copied()
        else {
            return Err(StorageStateError::Receiving);
        };
        if let Some(receiving) = receiving {
            self.first = Some(Failure::Geometry);
            self.geometry = Some(capacity_v1(&record.program));
            let Some(capacity) = self.geometry.as_ref()
                .and_then(|result| result.as_ref().ok()).copied()
            else {
                return Err(StorageStateError::Receiving);
            };
            self.first = Some(Failure::Payment);
            // The Native three-backing envelope covers the original program
            // allocation, its growth and old/new record backing concurrently.
            self.payment = Some(receiving.reserve_encoded_capacity_v1(capacity, 3 * (10 + 5) + 6));
            if !matches!(self.payment, Some(Ok(()))) {
                return Err(StorageStateError::Receiving);
            }
        }
        self.first = Some(Failure::Program);
        let program = record.program.canonical_bytes_retaining_v1(&mut self.program_encoding);
        if !selected {
            // The former canonical encoder's partial Vec ended before its
            // caller projected the returned semantic error.
            self.program_encoding =
                crate::lifecycle_atomic_snapshot::AtomicProgramEncodingOriginalV1::new();
        }
        self.program = Some(program.map_err(|_| StorageStateError::InvalidValue));
        let Some(Ok(program)) = self.program.as_ref() else {
            return Err(StorageStateError::Receiving);
        };
        self.first = Some(Failure::ProgramLength);
        self.program_length = Some(u32::try_from(program.len())
            .map_err(|_| StorageStateError::InvalidValue));
        let Some(program_length) = self.program_length.as_ref()
            .and_then(|result| result.as_ref().ok()).copied()
        else {
            return Err(StorageStateError::Receiving);
        };
        self.encoded = Some(Vec::with_capacity(104 + program.len()));
        let Some(bytes) = self.encoded.as_mut() else {
            std::process::abort();
        };
        bytes.extend_from_slice(ATOMIC_SNAPSHOT_MAGIC);
        bytes.extend_from_slice(&version.to_be_bytes());
        bytes.push(record.phase as u8);
        bytes.extend_from_slice(&key.key_id);
        bytes.extend_from_slice(&record.sandbox_id);
        bytes.extend_from_slice(&record.request_id);
        bytes.extend_from_slice(record.semantic_digest.as_bytes());
        bytes.extend_from_slice(record.transport_digest.as_bytes());
        bytes.extend_from_slice(&program_length.to_be_bytes());
        bytes.extend_from_slice(program);
        bytes.extend_from_slice(record.observation.unwrap_or(ObjectDigest::from_bytes([0; 32]))
            .as_bytes());
        if let Some(head) = record.post_head {
            bytes.extend_from_slice(&head.generation().to_be_bytes());
            bytes.extend_from_slice(head.digest().as_bytes());
        }
        self.first = Some(Failure::Mac);
        self.mac = Some(HmacSha256::new_from_slice(&key.secret)
            .map_err(|_| StorageStateError::InvalidValue));
        if !matches!(self.mac, Some(Ok(_))) {
            return Err(StorageStateError::Receiving);
        }
        let Some(Ok(mut mac)) = self.mac.take() else {
            std::process::abort();
        };
        mac.update(if version == ATOMIC_SNAPSHOT_VERSION_V3 {
            ATOMIC_SNAPSHOT_DOMAIN_V3
        } else {
            ATOMIC_SNAPSHOT_DOMAIN_V2
        });
        mac.update(&record.program.operation());
        mac.update(bytes);
        bytes.extend_from_slice(&mac.finalize().into_bytes());
        self.first = None;
        match self.encoded.take() {
            Some(bytes) => Ok(bytes),
            None => std::process::abort(),
        }
    }

    pub(super) fn dispose_ordinary_program(&mut self) {
        // A failed encoder's record bytes were the innermost local and ended
        // before its program bytes. Successful bytes have already moved out.
        drop(self.encoded.take());
        if matches!(self.program, Some(Ok(_))) {
            drop(self.program.take());
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            Failure::Geometry => self.geometry.as_ref()?.as_ref().err()
                .map(|cause| cause as &dyn std::error::Error),
            Failure::Payment => self.payment.as_ref()?.as_ref().err()
                .map(|cause| cause as &dyn std::error::Error),
            Failure::Version => self.version.as_ref()?.as_ref().err()
                .map(|cause| cause as &dyn std::error::Error),
            Failure::Program => self.program_encoding.failure()
                .map(|cause| cause as &dyn std::error::Error)
                .or_else(|| self.program.as_ref()?.as_ref().err()
                    .map(|cause| cause as &dyn std::error::Error)),
            Failure::ProgramLength => self.program_length.as_ref()?.as_ref().err()
                .map(|cause| cause as &dyn std::error::Error),
            Failure::Mac => self.mac.as_ref()?.as_ref().err()
                .map(|cause| cause as &dyn std::error::Error),
        }
    }

    pub(super) fn take_ordinary_failure(&mut self) -> StorageStateError {
        let cause = match self.first.take() {
            Some(Failure::Version) => self.version.take().and_then(Result::err),
            Some(Failure::Program) => self.program.take().and_then(Result::err),
            Some(Failure::ProgramLength) => self.program_length.take().and_then(Result::err),
            Some(Failure::Mac) => self.mac.take().and_then(Result::err),
            Some(Failure::Geometry | Failure::Payment) | None => None,
        };
        match cause {
            Some(cause) => cause,
            None => std::process::abort(),
        }
    }
}

/// Counts the exact existing canonical program grammar without cloning it.
///
/// # Errors
///
/// Returns the checked memory overflow when the reached field widths cannot fit.
pub(crate) fn program_wire_length_v1(
    program: &crate::DormantAtomicDatasetSnapshotV1,
) -> Result<usize, aos_sandbox_core::AccountingError> {
    let mut length: usize = 8 + 2 + 16 + 16 + 32 + 32 + 8 + 32 + 2 + 32;
    if program.format_version() == 2 {
        length += 32;
    }
    for member in program.members() {
        length = length.checked_add(2)
            .and_then(|length| length.checked_add(member.source_name().len()))
            .and_then(|length| length.checked_add(8 + 2))
            .and_then(|length| length.checked_add(member.destination_name().len()))
            .and_then(|length| length.checked_add(32 + 32))
            .ok_or(aos_sandbox_core::AccountingError::ArithmeticOverflow {
                dimension: aos_sandbox_core::ResourceDimension::MemoryBytes,
            })?;
    }
    Ok(length)
}

/// Prices the existing program allocation and growth before its encoder runs.
///
/// # Errors
///
/// Returns the checked memory overflow when the reached buffer bound cannot fit.
pub(crate) fn program_capacity_v1(
    program: &crate::DormantAtomicDatasetSnapshotV1,
) -> Result<usize, aos_sandbox_core::AccountingError> {
    let length = program_wire_length_v1(program)?;
    program.members().len().checked_mul(192)
        .and_then(|bytes| bytes.checked_add(192))
        .zip(length.checked_mul(2))
        .and_then(|(initial, body)| initial.checked_add(body))
        .ok_or(aos_sandbox_core::AccountingError::ArithmeticOverflow {
            dimension: aos_sandbox_core::ResourceDimension::MemoryBytes,
        })
}

/// Prices reached program and record Vec growth together, before either Vec.
fn capacity_v1(
    program: &crate::DormantAtomicDatasetSnapshotV1,
) -> Result<usize, aos_sandbox_core::AccountingError> {
    program_capacity_v1(program)?
        // Existing V3 record overhead231 dominates V2 overhead191.
        .checked_add(231)
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<AtomicEncodingOriginalV1>()))
        .ok_or(aos_sandbox_core::AccountingError::ArithmeticOverflow {
            dimension: aos_sandbox_core::ResourceDimension::MemoryBytes,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reached_program_geometry_matches_real_v2_and_v3_record_widths() {
        let program = crate::lifecycle_atomic_snapshot::sample_atomic_snapshot_program_for_test();
        let canonical = program.canonical_bytes().unwrap();
        assert_eq!(program_wire_length_v1(&program).unwrap(), canonical.len());
        let key = super::super::tests::key(41);
        let mut record = AtomicDatasetSnapshotRecordV1 {
            phase: AtomicDatasetSnapshotPhaseV1::Committed,
            program,
            observation: Some(ObjectDigest::from_bytes([42; 32])),
            sandbox_id: [43; 16],
            request_id: [44; 16],
            semantic_digest: ObjectDigest::from_bytes([45; 32]),
            transport_digest: ObjectDigest::from_bytes([46; 32]),
            post_head: None,
        };
        let mut ordinary = AtomicEncodingOriginalV1::new();

        let encoded = ordinary.encode(&record, &key, None).unwrap();

        assert_eq!(encoded.len(), canonical.len() + 191);
        assert_eq!(&encoded[8..10], &ATOMIC_SNAPSHOT_VERSION_V2.to_be_bytes());
        assert_eq!(ordinary.program.as_ref().unwrap().as_ref().unwrap(), &canonical);
        ordinary.dispose_ordinary_program();
        assert!(ordinary.program.is_none());

        record.post_head = Some(CatalogBindingV1::from_publisher(
            10, ObjectDigest::from_bytes([47; 32]),
        ).unwrap());
        let mut checkpointed = AtomicEncodingOriginalV1::new();
        let encoded = checkpointed.encode(&record, &key, None).unwrap();

        assert_eq!(encoded.len(), canonical.len() + 231);
        assert_eq!(&encoded[8..10], &ATOMIC_SNAPSHOT_VERSION_V3.to_be_bytes());
        assert_eq!(decode_atomic_snapshot_record([1; 16], &encoded, &key).unwrap().post_head,
            record.post_head);
    }
}
