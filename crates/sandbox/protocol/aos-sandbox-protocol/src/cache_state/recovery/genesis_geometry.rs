//! Checks the existing Genesis-only checkpoint shape before typed allocation.
//!
//! The ordinary decoder remains responsible for complete canonical and semantic
//! validation. This borrowed preflight rejects arrays that bootstrap already
//! forbids, so their advertised capacities cannot allocate before rejection.
//!
//! ```text
//! AOSTCP01 | checkpoint | baselines=0 | heads=0 | global | digest
//! global = header | partition | node-quota | projects | all other groups empty
//! ```

use super::*;

pub fn genesis_checkpoint_project_count(
    partition: PhysicalPartitionId,
    bytes: &[u8],
    limits: CacheRecoveryLimitsV1,
) -> Result<usize, RecoveryError> {
    let limits = limits.validate()?;
    let mut reader = RecoveryReader::new(bytes, recovery_read_error);
    read_component_header(&mut reader, TYPED_CHECKPOINT_MAGIC, limits.maximum_payload_bytes)?;
    let checkpoint = decode_checkpoint(read_length_prefixed(&mut reader, CHECKPOINT_BYTES)?)?;
    if checkpoint.sequence != 1 {
        return Err(RecoveryError::PayloadMismatch);
    }
    require_empty_count(&mut reader)?;
    require_empty_count(&mut reader)?;
    let global = read_length_prefixed(&mut reader, limits.maximum_payload_bytes)?;
    reader.digest()?;
    reader.finish()?;

    let mut reader = RecoveryReader::new(global, recovery_read_error);
    read_component_header(&mut reader, b"AOSGLB01", limits.maximum_payload_bytes)?;
    read_expected_digest(&mut reader, partition.digest())?;
    read_node_quota(&mut reader, partition)?;
    let projects = read_count(&mut reader, limits.maximum_subjects)?;
    // Each project has identity16, partition32 and five u64 ceilings. Reading
    // those existing fields uses fixed scratch and rejects truncated counts
    // before any project-quota Vec or accounting map can be reserved.
    for _ in 0..projects {
        read_project_quota(&mut reader, partition)?;
    }
    require_empty_count(&mut reader)?;
    require_empty_count(&mut reader)?;
    reader.zeros(2)?;
    require_empty_count(&mut reader)?;
    require_empty_count(&mut reader)?;
    reader.zeros(1)?;
    reader.digest()?;
    reader.finish()?;
    Ok(projects)
}

fn require_empty_count(reader: &mut RecoveryReader<'_>) -> Result<(), RecoveryError> {
    if reader.u32()? != 0 {
        return Err(RecoveryError::PayloadMismatch);
    }
    Ok(())
}
