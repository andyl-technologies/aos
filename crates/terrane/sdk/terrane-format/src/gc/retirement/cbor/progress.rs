//! Encodes permanent owner selectors, operations and bounded pass deltas.
//!
//! ```text
//! owner = [0] / [1, operation-key, authorization-digest]
//! observation = [kind, instance, state] / [2, cycle, instance, state]
//! ```

use super::*;

impl Record for PermanentOwnerSelection {
    fn read(decoder: &mut Decoder<'_>) -> Result<Self, RetirementError> {
        let count = decoder.array(3)?;
        match (decoder.uint()?, count) {
            (0, 1) => Ok(Self::CopiedVisibility),
            (1, 3) => {
                let pointer = RecordPointer {
                    key: text(decoder)?,
                    digest: digest(decoder)?,
                };
                validation::operation_key(&pointer.key)?;
                Ok(Self::Permanent(pointer))
            }
            _ => Err(RetirementError::Schema),
        }
    }

    fn write(&self, output: &mut Vec<u8>) -> Result<(), RetirementError> {
        match self {
            Self::CopiedVisibility => {
                write_array(output, 1);
                write_uint(output, 0);
            }
            Self::Permanent(pointer) => {
                validation::operation_key(&pointer.key)?;
                write_array(output, 3);
                write_uint(output, 1);
                write_text(output, &pointer.key);
                write_bytes(output, &pointer.digest);
            }
        }
        Ok(())
    }
}

impl Record for PermanentBurnOwner {
    fn read(decoder: &mut Decoder<'_>) -> Result<Self, RetirementError> {
        array(decoder, 2)?;
        let value = Self {
            pack: digest(decoder)?,
            selection: PermanentOwnerSelection::read(decoder)?,
        };
        validation::burn_owner(&value)?;
        Ok(value)
    }

    fn write(&self, output: &mut Vec<u8>) -> Result<(), RetirementError> {
        validation::burn_owner(self)?;
        write_array(output, 2);
        write_bytes(output, &self.pack);
        self.selection.write(output)
    }
}

impl Record for PermanentDeleteOperation {
    fn read(decoder: &mut Decoder<'_>) -> Result<Self, RetirementError> {
        array(decoder, 6)?;
        if decoder.uint()? != 2 {
            return Err(RetirementError::Schema);
        }
        let revision = decoder.uint()?;
        let phase = match decoder.uint()? {
            0 => OperationPhase::Proposed,
            1 => OperationPhase::Owned,
            2 => OperationPhase::Cancelled,
            _ => return Err(RetirementError::Schema),
        };
        let authorization = PermanentDeleteAuthorization::read(decoder)?;
        let owner = optional(decoder, slot)?;
        let pass = optional(decoder, pointer)?;
        let value = Self {
            revision,
            phase,
            authorization,
            owner,
            pass,
        };
        validation::operation(&value)?;
        Ok(value)
    }

    fn write(&self, output: &mut Vec<u8>) -> Result<(), RetirementError> {
        validation::operation(self)?;
        write_array(output, 6);
        write_uint(output, 2);
        write_uint(output, self.revision);
        write_uint(
            output,
            match self.phase {
                OperationPhase::Proposed => 0,
                OperationPhase::Owned => 1,
                OperationPhase::Cancelled => 2,
            },
        );
        self.authorization.write(output)?;
        write_optional(output, self.owner.as_ref(), write_slot)?;
        write_optional(output, self.pass.as_ref(), write_pointer)
    }
}

fn instance(decoder: &mut Decoder<'_>) -> Result<ObservedInstance, RetirementError> {
    let count = decoder.array(3)?;
    match (decoder.uint()?, count) {
        (0, 1) => Ok(ObservedInstance::Unversioned),
        (1, 3) => {
            let kind = decoder.uint()?;
            let handle = blob(decoder, 4096)?;
            if handle.is_empty() {
                return Err(RetirementError::Schema);
            }
            match kind {
                0 => Ok(ObservedInstance::Version(handle)),
                1 => Ok(ObservedInstance::Marker(handle)),
                _ => Err(RetirementError::Schema),
            }
        }
        _ => Err(RetirementError::Schema),
    }
}

fn write_instance(value: &ObservedInstance, output: &mut Vec<u8>) {
    match value {
        ObservedInstance::Unversioned => {
            write_array(output, 1);
            write_uint(output, 0);
        }
        ObservedInstance::Version(handle) | ObservedInstance::Marker(handle) => {
            write_array(output, 3);
            write_uint(output, 1);
            write_uint(
                output,
                u64::from(matches!(value, ObservedInstance::Marker(_))),
            );
            write_bytes(output, handle);
        }
    }
}

fn observation(decoder: &mut Decoder<'_>) -> Result<RequestObservation, RetirementError> {
    let count = decoder.array(4)?;
    let artifact = match (decoder.uint()?, count) {
        (0, 3) => ObservedArtifact::Pack,
        (1, 3) => ObservedArtifact::Index,
        (2, 4) => ObservedArtifact::Trash(decoder.uint()?),
        _ => return Err(RetirementError::Schema),
    };
    let instance = instance(decoder)?;
    let state = match decoder.uint()? {
        0 => ObservationState::Planned,
        1 => ObservationState::ConfirmedAbsent,
        2 => ObservationState::Indeterminate,
        3 => ObservationState::Deferred,
        _ => return Err(RetirementError::Schema),
    };
    Ok(RequestObservation {
        artifact,
        instance,
        state,
    })
}

fn write_observation(value: &RequestObservation, output: &mut Vec<u8>) {
    write_array(
        output,
        if matches!(value.artifact, ObservedArtifact::Trash(_)) {
            4
        } else {
            3
        },
    );
    match value.artifact {
        ObservedArtifact::Pack => write_uint(output, 0),
        ObservedArtifact::Index => write_uint(output, 1),
        ObservedArtifact::Trash(cycle) => {
            write_uint(output, 2);
            write_uint(output, cycle);
        }
    }
    write_instance(&value.instance, output);
    write_uint(
        output,
        match value.state {
            ObservationState::Planned => 0,
            ObservationState::ConfirmedAbsent => 1,
            ObservationState::Indeterminate => 2,
            ObservationState::Deferred => 3,
        },
    );
}

impl Record for PermanentDeletePass {
    fn read(decoder: &mut Decoder<'_>) -> Result<Self, RetirementError> {
        let fields = decoder.map(14)?;
        if !matches!(fields, 13 | 14) {
            return Err(RetirementError::Schema);
        }
        version(decoder, 2)?;
        key(decoder, 1)?;
        let authorization_digest = digest(decoder)?;
        key(decoder, 2)?;
        let owner = slot(decoder)?;
        key(decoder, 3)?;
        let revision = decoder.uint()?;
        key(decoder, 4)?;
        array(decoder, 2)?;
        let pass = decoder.uint()?;
        let event = decoder.uint()?;
        key(decoder, 5)?;
        let predecessor = slot(decoder)?;
        key(decoder, 6)?;
        let state = PublicationState::decode(decoder.bytes(MAX_RECORD_BYTES)?)?;
        key(decoder, 7)?;
        let lease = lease(decoder)?;
        key(decoder, 8)?;
        let backend = backend(decoder)?;
        key(decoder, 9)?;
        let phase = match decoder.uint()? {
            0 => PassPhase::Open,
            1 => PassPhase::PassCompleted,
            _ => return Err(RetirementError::Schema),
        };
        key(decoder, 10)?;
        let count = decoder.array(MAX_OBSERVATIONS)?;
        let mut observations = Vec::with_capacity(count);
        for _ in 0..count {
            observations.push(observation(decoder)?);
        }
        key(decoder, 11)?;
        array(decoder, 3)?;
        let mut coverage = [PassCoverage::Unknown; 3];
        for (kind, row) in coverage.iter_mut().enumerate() {
            array(decoder, 2)?;
            if decoder.uint()? != kind as u64 {
                return Err(RetirementError::Schema);
            }
            *row = match decoder.uint()? {
                0 => PassCoverage::Unknown,
                1 => PassCoverage::CandidateTraversalCompleted,
                2 => PassCoverage::QualifiedAllVersionAbsenceAtObservation,
                _ => return Err(RetirementError::Schema),
            };
        }
        key(decoder, 12)?;
        let nonce = digest(decoder)?;
        let placement_fence = if fields == 14 {
            key(decoder, 13)?;
            Some(pointer(decoder)?)
        } else {
            None
        };
        let value = Self {
            authorization_digest,
            owner,
            revision,
            pass,
            event,
            predecessor,
            state,
            lease,
            backend,
            phase,
            observations,
            coverage,
            nonce,
            placement_fence,
        };
        validation::pass(&value)?;
        Ok(value)
    }

    fn write(&self, output: &mut Vec<u8>) -> Result<(), RetirementError> {
        validation::pass(self)?;
        header(output, 13 + usize::from(self.placement_fence.is_some()));
        write_uint(output, 1);
        write_bytes(output, &self.authorization_digest);
        write_uint(output, 2);
        write_slot(&self.owner, output)?;
        field(output, 3, self.revision);
        write_uint(output, 4);
        write_array(output, 2);
        write_uint(output, self.pass);
        write_uint(output, self.event);
        write_uint(output, 5);
        write_slot(&self.predecessor, output)?;
        write_uint(output, 6);
        write_bytes(output, &self.state.encode()?);
        write_uint(output, 7);
        output.extend(self.lease.encode()?);
        write_uint(output, 8);
        output.extend(self.backend.encode()?);
        field(output, 9, u64::from(self.phase == PassPhase::PassCompleted));
        write_uint(output, 10);
        write_array(output, self.observations.len());
        for row in &self.observations {
            write_observation(row, output);
        }
        write_uint(output, 11);
        write_array(output, 3);
        for (kind, coverage) in self.coverage.iter().enumerate() {
            write_array(output, 2);
            write_uint(output, kind as u64);
            write_uint(
                output,
                match coverage {
                    PassCoverage::Unknown => 0,
                    PassCoverage::CandidateTraversalCompleted => 1,
                    PassCoverage::QualifiedAllVersionAbsenceAtObservation => 2,
                },
            );
        }
        write_uint(output, 12);
        write_bytes(output, &self.nonce);
        if let Some(fence) = &self.placement_fence {
            write_uint(output, 13);
            write_pointer(fence, output)?;
        }
        Ok(())
    }
}
