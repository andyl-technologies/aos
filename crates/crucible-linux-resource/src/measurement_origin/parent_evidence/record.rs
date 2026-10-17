//! Receives the second sealed evidence record from the same live PID1 issuer.
//!
//! The raw frame is descriptive data. Only the already-authenticated original
//! issuer channel can supply it to the private carrier constructor. The caller
//! retains the sealed File through all subsequent actor purposes and aliases.

use super::{
    AuthenticatedParentInvocation, CertifiedMeasurementMode, CertifiedNativeRoleEvidence,
    VerifiedImageInventory,
};
use crate::measurement_origin::{
    MeasurementInvocationOrigin, MeasurementOriginError, OriginalInterval, fcntl_get_seals,
    receive_record, required_seals,
};
use std::fs::File;
use std::io::{Read, Seek};
use std::os::unix::fs::MetadataExt;

const FRAME_BYTES: usize = 224;
const MAGIC: &[u8; 8] = b"CPARNT02";

pub(super) fn receive(
    origin: MeasurementInvocationOrigin,
) -> Result<AuthenticatedParentInvocation, MeasurementOriginError> {
    let interval = OriginalInterval {
        start_ns: origin.start_ns,
        end_ns: origin.end_ns,
    };
    let mut file = receive_record(&origin._issuer, interval)?;
    interval.before()?;
    if interval.after_kernel(fcntl_get_seals(&file))? != required_seals() {
        return Err(MeasurementOriginError::Authentication(
            "parent evidence seals",
        ));
    }
    interval.before()?;
    let metadata = interval.after_io(file.metadata())?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.len() != FRAME_BYTES as u64 {
        return Err(MeasurementOriginError::Authentication(
            "parent evidence extent/owner",
        ));
    }
    interval.before()?;
    interval.after_io(file.rewind())?;
    let mut frame = [0; FRAME_BYTES];
    interval.before()?;
    interval.after_io(file.read_exact(&mut frame))?;
    let evidence = authenticated_fields(&origin, frame, file)?;
    origin.remaining()?;
    Ok(AuthenticatedParentInvocation { origin, evidence })
}

fn authenticated_fields(
    origin: &MeasurementInvocationOrigin,
    frame: [u8; FRAME_BYTES],
    file: File,
) -> Result<CertifiedNativeRoleEvidence, MeasurementOriginError> {
    let hash = |offset: usize| {
        let mut value = [0; 32];
        value.copy_from_slice(&frame[offset..offset + 32]);
        value
    };
    let word = |offset: usize| {
        let mut value = [0; 8];
        value.copy_from_slice(&frame[offset..offset + 8]);
        u64::from_le_bytes(value)
    };
    let mode = match frame[145] {
        0 => CertifiedMeasurementMode::NativeOnly,
        1 => CertifiedMeasurementMode::KernelMeasurement,
        _ => {
            return Err(MeasurementOriginError::Authentication(
                "parent evidence family",
            ));
        }
    };
    let expected_mode = match origin.policy.mode {
        crate::measurement_origin::StaticMode::NativeOnly => CertifiedMeasurementMode::NativeOnly,
        crate::measurement_origin::StaticMode::KernelMeasurement => {
            CertifiedMeasurementMode::KernelMeasurement
        }
    };
    let operator_digest = hash(8);
    let image_digest = hash(40);
    let source_digest = hash(72);
    let incarnation = hash(104);
    let workflow_digest = hash(192);
    let generation = word(136);
    if &frame[..8] != MAGIC
        || frame[146..152] != [0; 6]
        || operator_digest != origin.policy_digest
        || workflow_digest == [0; 32]
        || image_digest == [0; 32]
        || source_digest == [0; 32]
        || incarnation == [0; 32]
        || generation == 0
        || mode != expected_mode
        || u64::from(frame[144]) != origin.policy.native_count
        || origin.policy.actor_task_limit != 4096
        || origin.policy.actor_descriptors != 1024
        || origin.policy.actor_cpu_slots != 10
        || origin.policy.actor_resident_bytes != 16 << 30
        || origin.policy.host_memory_bytes != 20 << 30
        || origin.policy.host_backing_bytes != 64 << 30
        || !matches!(frame[144], 1 | 2 | 4)
        || word(152) != 4096
        || word(160) != 1024
        || word(168) != 16 << 30
        || word(176) != 20 << 30
        || word(184) != 64 << 30
    {
        return Err(MeasurementOriginError::Authentication(
            "parent evidence binding",
        ));
    }
    Ok(CertifiedNativeRoleEvidence {
        images: VerifiedImageInventory {
            digest: image_digest,
            source_digest,
            _record: file,
        },
        operator_digest,
        workflow_digest,
        incarnation,
        generation,
        mode,
        native_count: frame[144],
    })
}
