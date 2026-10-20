//! Encodes immutable sweep and copied retirement premises and preparation.
//!
//! ```text
//! artifacts = [pack, index, trash] / [null, null, NEW-barrier]
//! ```

use super::*;

impl Record for PermanentDeleteAuthorization {
    fn read(decoder: &mut Decoder<'_>) -> Result<Self, RetirementError> {
        let fields = decoder.map(17)?;
        if !matches!(fields, 14 | 16 | 17) {
            return Err(RetirementError::Schema);
        }
        version(decoder, 2)?;
        key(decoder, 1)?;
        let nonce = digest(decoder)?;
        key(decoder, 2)?;
        let backend = backend(decoder)?;
        key(decoder, 3)?;
        let exclusion = exclusion(decoder)?;
        key(decoder, 4)?;
        let lease = lease(decoder)?;
        key(decoder, 5)?;
        let deletion_seconds = decoder.uint()?;
        key(decoder, 6)?;
        array(decoder, 3)?;

        let (artifacts, barrier, witness) = if fields == 14 {
            let artifacts = [artifact(decoder)?, artifact(decoder)?, artifact(decoder)?];
            key(decoder, 7)?;
            (
                Some(artifacts),
                None,
                Some(blob(decoder, MAX_RECORD_BYTES)?),
            )
        } else {
            null(decoder)?;
            null(decoder)?;
            (None, Some(barrier(decoder)?), None)
        };
        key(decoder, 8)?;
        let tombstone = blob(decoder, 128)?;
        key(decoder, 9)?;
        let deletion_elapsed_nanos = decoder.uint()?;
        key(decoder, 10)?;
        let fence = pointer(decoder)?;
        key(decoder, 11)?;
        let grace_seconds = decoder.uint()?;
        key(decoder, 12)?;
        let grace_elapsed_nanos = decoder.uint()?;
        key(decoder, 13)?;
        if decoder.uint()? != 1 {
            return Err(RetirementError::Schema);
        }

        let value = match (artifacts, barrier, witness) {
            (Some(artifacts), None, Some(witness)) => Self::Sweep(RemoteSweepDeleteAuthorization {
                nonce,
                backend,
                exclusion,
                lease,
                deletion_seconds,
                artifacts,
                witness,
                tombstone,
                deletion_elapsed_nanos,
                fence,
                grace_seconds,
                grace_elapsed_nanos,
            }),
            (None, Some(barrier), None) => {
                key(decoder, 14)?;
                if decoder.uint()? != 1 {
                    return Err(RetirementError::Schema);
                }
                key(decoder, 15)?;
                let genesis = slot(decoder)?;
                key(decoder, 16)?;
                let preparation = slot(decoder)?;
                let lineage_fence = if fields == 17 {
                    key(decoder, 17)?;
                    Some(pointer(decoder)?)
                } else {
                    None
                };
                Self::Copied(CopiedRetirementAuthorization {
                    nonce,
                    backend,
                    exclusion,
                    lease,
                    deletion_seconds,
                    barrier,
                    tombstone,
                    deletion_elapsed_nanos,
                    fence,
                    grace_seconds,
                    grace_elapsed_nanos,
                    genesis,
                    preparation,
                    lineage_fence,
                })
            }
            _ => return Err(RetirementError::Schema),
        };
        validation::authorization(&value)?;
        Ok(value)
    }

    fn write(&self, output: &mut Vec<u8>) -> Result<(), RetirementError> {
        validation::authorization(self)?;
        let (
            nonce,
            backend,
            exclusion,
            lease,
            deletion_seconds,
            tombstone,
            deletion_elapsed_nanos,
            fence,
            grace_seconds,
            grace_elapsed_nanos,
        ) = match self {
            Self::Sweep(value) => {
                header(output, 14);
                (
                    &value.nonce,
                    &value.backend,
                    &value.exclusion,
                    &value.lease,
                    value.deletion_seconds,
                    &value.tombstone,
                    value.deletion_elapsed_nanos,
                    &value.fence,
                    value.grace_seconds,
                    value.grace_elapsed_nanos,
                )
            }
            Self::Copied(value) => {
                header(output, 16 + usize::from(value.lineage_fence.is_some()));
                (
                    &value.nonce,
                    &value.backend,
                    &value.exclusion,
                    &value.lease,
                    value.deletion_seconds,
                    &value.tombstone,
                    value.deletion_elapsed_nanos,
                    &value.fence,
                    value.grace_seconds,
                    value.grace_elapsed_nanos,
                )
            }
        };
        write_uint(output, 1);
        write_bytes(output, nonce);
        write_uint(output, 2);
        output.extend(backend.encode()?);
        write_uint(output, 3);
        write_exclusion(exclusion, output);
        write_uint(output, 4);
        output.extend(lease.encode()?);
        field(output, 5, deletion_seconds);
        write_uint(output, 6);
        write_array(output, 3);
        match self {
            Self::Sweep(value) => {
                for artifact in &value.artifacts {
                    write_artifact(artifact, output);
                }
                write_uint(output, 7);
                write_bytes(output, &value.witness);
            }
            Self::Copied(value) => {
                output.extend_from_slice(&[0xf6, 0xf6]);
                write_barrier(&value.barrier, output);
            }
        }
        write_uint(output, 8);
        write_bytes(output, tombstone);
        field(output, 9, deletion_elapsed_nanos);
        write_uint(output, 10);
        write_pointer(fence, output)?;
        field(output, 11, grace_seconds);
        field(output, 12, grace_elapsed_nanos);
        field(output, 13, 1);
        if let Self::Copied(value) = self {
            field(output, 14, 1);
            write_uint(output, 15);
            write_slot(&value.genesis, output)?;
            write_uint(output, 16);
            write_slot(&value.preparation, output)?;
            if let Some(pointer) = &value.lineage_fence {
                write_uint(output, 17);
                write_pointer(pointer, output)?;
            }
        }
        Ok(())
    }
}

impl Record for RemoteSweepDeleteAuthorization {
    fn read(decoder: &mut Decoder<'_>) -> Result<Self, RetirementError> {
        match PermanentDeleteAuthorization::read(decoder)? {
            PermanentDeleteAuthorization::Sweep(value) => Ok(value),
            _ => Err(RetirementError::Schema),
        }
    }

    fn write(&self, output: &mut Vec<u8>) -> Result<(), RetirementError> {
        PermanentDeleteAuthorization::Sweep(self.clone()).write(output)
    }
}

impl Record for CopiedRetirementAuthorization {
    fn read(decoder: &mut Decoder<'_>) -> Result<Self, RetirementError> {
        match PermanentDeleteAuthorization::read(decoder)? {
            PermanentDeleteAuthorization::Copied(value) => Ok(value),
            _ => Err(RetirementError::Schema),
        }
    }

    fn write(&self, output: &mut Vec<u8>) -> Result<(), RetirementError> {
        PermanentDeleteAuthorization::Copied(self.clone()).write(output)
    }
}

impl Record for CopiedRetirementPlan {
    fn read(decoder: &mut Decoder<'_>) -> Result<Self, RetirementError> {
        if decoder.map(10)? != 10 {
            return Err(RetirementError::Schema);
        }
        version(decoder, 2)?;
        key(decoder, 1)?;
        let nonce = digest(decoder)?;
        key(decoder, 2)?;
        let backend = backend(decoder)?;
        key(decoder, 3)?;
        let exclusion = exclusion(decoder)?;
        key(decoder, 4)?;
        let lease = lease(decoder)?;
        key(decoder, 5)?;
        let genesis = slot(decoder)?;
        key(decoder, 6)?;
        let fence = pointer(decoder)?;
        key(decoder, 7)?;
        let tombstone = blob(decoder, 128)?;
        key(decoder, 8)?;
        let grace_seconds = decoder.uint()?;
        key(decoder, 9)?;
        let deletion_seconds = decoder.uint()?;
        let value = Self {
            nonce,
            backend,
            exclusion,
            lease,
            genesis,
            fence,
            tombstone,
            grace_seconds,
            deletion_seconds,
        };
        validation::plan(&value)?;
        Ok(value)
    }

    fn write(&self, output: &mut Vec<u8>) -> Result<(), RetirementError> {
        validation::plan(self)?;
        header(output, 10);
        write_uint(output, 1);
        write_bytes(output, &self.nonce);
        write_uint(output, 2);
        output.extend(self.backend.encode()?);
        write_uint(output, 3);
        write_exclusion(&self.exclusion, output);
        write_uint(output, 4);
        output.extend(self.lease.encode()?);
        write_uint(output, 5);
        write_slot(&self.genesis, output)?;
        write_uint(output, 6);
        write_pointer(&self.fence, output)?;
        write_uint(output, 7);
        write_bytes(output, &self.tombstone);
        field(output, 8, self.grace_seconds);
        field(output, 9, self.deletion_seconds);
        Ok(())
    }
}

impl Record for CopiedRetirementPreparation {
    fn read(decoder: &mut Decoder<'_>) -> Result<Self, RetirementError> {
        array(decoder, 4)?;
        if decoder.uint()? != 2 {
            return Err(RetirementError::Schema);
        }
        let revision = decoder.uint()?;
        let phase = match decoder.uint()? {
            3 => PreparationPhase::Preparing,
            4 => PreparationPhase::Abandoned,
            _ => return Err(RetirementError::Schema),
        };
        let plan = CopiedRetirementPlan::read(decoder)?;
        Ok(Self {
            revision,
            phase,
            plan,
        })
    }

    fn write(&self, output: &mut Vec<u8>) -> Result<(), RetirementError> {
        write_array(output, 4);
        write_uint(output, 2);
        write_uint(output, self.revision);
        write_uint(
            output,
            match self.phase {
                PreparationPhase::Preparing => 3,
                PreparationPhase::Abandoned => 4,
            },
        );
        self.plan.write(output)
    }
}
