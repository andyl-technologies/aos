//! Retains actual helper output and its semantic interpretation.
//!
//! The selected State caller pays each reached carrier before allocating it.
//! This owner creates no worker, account, effect, or service authority.

use super::*;

/// Holds the real returned wire output independently of transport cleanup.
pub(super) struct RecoveryHelperResultsV1 {
    pub(super) outputs: Vec<Result<ZfsProcessOutput, ZfsHelperError>>,
    output_allocation: Option<Result<(), std::collections::TryReserveError>>,
    pub(super) interpretations: Vec<HelperOutputInterpretationV1>,
    interpretation_allocation: Option<Result<(), std::collections::TryReserveError>>,
    shape: Option<Result<(usize, usize), aos_sandbox_model::AccountingError>>,
    payment: Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>,
    armed: bool,
}

impl RecoveryHelperResultsV1 {
    pub(super) const fn new() -> Self {
        Self {
            outputs: Vec::new(),
            output_allocation: None,
            interpretations: Vec::new(),
            interpretation_allocation: None,
            shape: None,
            payment: None,
            armed: false,
        }
    }

    pub(super) fn prepare_atomic_v1(
        &mut self,
        receiving: &mut crate::state::encoding::StateEncodingLoanV1<'_, '_>,
        members: usize,
        executable_bytes: usize,
    ) -> Result<(), ZfsHelperError> {
        let shape = atomic_shape_v1(&self.outputs, &self.interpretations, members, executable_bytes);
        self.prepare_slots_v1(receiving, shape)
    }

    pub(super) fn prepare_mutation_v1(
        &mut self,
        receiving: &mut crate::state::encoding::StateEncodingLoanV1<'_, '_>,
        executable_bytes: usize,
    ) -> Result<(), ZfsHelperError> {
        let shape = (|| {
            let overflow = || aos_sandbox_model::AccountingError::ArithmeticOverflow {
                dimension: aos_sandbox_model::ResourceDimension::MemoryBytes,
            };
            let outputs = self.outputs.len().checked_add(1)
                .and_then(|slots| slots.checked_mul(std::mem::size_of::<Result<ZfsProcessOutput, ZfsHelperError>>()))
                .ok_or_else(overflow)?;
            let interpretations = self.interpretations.len().checked_add(1)
                .and_then(|slots| slots.checked_mul(std::mem::size_of::<HelperOutputInterpretationV1>()))
                .ok_or_else(overflow)?;
            let bytes = outputs.checked_add(interpretations)
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Self>()))
                .and_then(|bytes| bytes.checked_add(executable_bytes))
                .and_then(|bytes| bytes.checked_add(MAXIMUM_STDOUT_BYTES + MAXIMUM_STDERR_BYTES))
                .ok_or_else(overflow)?;
            Ok((bytes, 0))
        })();
        self.prepare_slots_v1(receiving, shape)
    }

    fn prepare_slots_v1(
        &mut self,
        receiving: &mut crate::state::encoding::StateEncodingLoanV1<'_, '_>,
        shape: Result<(usize, usize), aos_sandbox_model::AccountingError>,
    ) -> Result<(), ZfsHelperError> {
        if self.failure().is_some() {
            return Err(StorageStateError::Receiving.into());
        }
        self.shape = Some(shape);
        let Some((bytes, cells)) = self.shape.as_ref()
            .and_then(|result| result.as_ref().ok()).copied()
        else {
            return Err(StorageStateError::Receiving.into());
        };
        self.payment = Some(receiving.reserve_encoded_capacity_v1(bytes, cells));
        if !matches!(self.payment, Some(Ok(()))) {
            return Err(StorageStateError::Receiving.into());
        }

        self.output_allocation = Some(self.outputs.try_reserve_exact(1));
        if !matches!(self.output_allocation, Some(Ok(()))) {
            return Err(StorageStateError::Receiving.into());
        }
        self.interpretation_allocation = Some(self.interpretations.try_reserve_exact(1));
        if !matches!(self.interpretation_allocation, Some(Ok(()))) {
            return Err(StorageStateError::Receiving.into());
        }
        self.armed = true;
        Ok(())
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.shape.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &dyn std::error::Error)
            .or_else(|| self.payment.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.output_allocation.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.interpretation_allocation.as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error))
            .or_else(|| {
                // Each successful interpretation accompanies one output. A
                // failed output terminates this closed caller before parsing.
                self.outputs.iter().zip(&self.interpretations).find_map(|(output, interpretation)| {
                    output.as_ref().err().map(resolve_helper_cause)
                        .or_else(|| interpretation.actual_failure())
                })
            })
            .or_else(|| self.outputs.iter().find_map(|result| result.as_ref().err())
                .map(resolve_helper_cause))
    }

    pub(super) fn require_positive_after_posts_v1(&self) -> Result<(), ZfsHelperError> {
        if self.failure().is_some() || self.outputs.len() != self.interpretations.len() {
            return Err(StorageStateError::Receiving.into());
        }
        Ok(())
    }

    pub(super) fn complete_positive_disposal_v1(&mut self) {
        self.armed = false;
        self.outputs = Vec::new();
        self.interpretations = Vec::new();
    }
}

fn atomic_shape_v1(
    outputs: &[Result<ZfsProcessOutput, ZfsHelperError>],
    interpretations: &[HelperOutputInterpretationV1],
    members: usize,
    executable_bytes: usize,
) -> Result<(usize, usize), aos_sandbox_model::AccountingError> {
    let output_bytes = outputs.len().checked_add(1).and_then(|slots| {
        slots.checked_mul(std::mem::size_of::<Result<ZfsProcessOutput, ZfsHelperError>>())
    });
    let interpretation_bytes = interpretations.len().checked_add(1).and_then(|slots| {
        slots.checked_mul(std::mem::size_of::<HelperOutputInterpretationV1>())
    });
    let bytes = output_bytes.zip(interpretation_bytes)
        .and_then(|(output, interpretation)| output.checked_add(interpretation))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<RecoveryHelperResultsV1>()))
        .and_then(|bytes| {
            members.max(4).checked_mul(
                std::mem::size_of::<u64>() + std::mem::size_of::<(&str, u64)>(),
            ).and_then(|rows| bytes.checked_add(rows))
        })
        .and_then(|bytes| bytes.checked_add(executable_bytes))
        .ok_or(aos_sandbox_model::AccountingError::ArithmeticOverflow {
            dimension: aos_sandbox_model::ResourceDimension::MemoryBytes,
        })?;
    // The enclosing model stage separately pays actual returned stdout and
    // stderr (128 KiB). This reached debit pays control/backing carriers,
    // the GUID collection and the executable clone before physical entry.
    // Three copies: owner7 + interpretation10 + digest owner5 + outputResult1
    // + output fields4, then program/argument/result/disposition controls6 + shape pair2.
    let cells = members.max(4).checked_mul(3)
        .and_then(|rows| rows.checked_add(3 * (7 + 10 + 5 + 1 + 4) + 8))
        .ok_or(aos_sandbox_model::AccountingError::ArithmeticOverflow {
            dimension: aos_sandbox_model::ResourceDimension::MetadataEntries,
        })?;
    Ok((bytes, cells))
}

/// Recognizes only the actual Native marker, preserving earlier concrete IO.
pub(super) fn resolve_helper_cause(cause: &ZfsHelperError) -> &(dyn std::error::Error + 'static) {
    if let ZfsHelperError::Backend(worker) = cause {
        if let Some(marker) = worker.physical_native_refusal_v1() {
            return marker;
        }
    }
    cause
}

impl Drop for RecoveryHelperResultsV1 {
    fn drop(&mut self) {
        if self.armed {
            // Only the actual outer all-positive posts/disposition can release
            // selected response owners. Negative/unwinding paths stay resident.
            std::process::abort();
        }
    }
}

pub(super) enum HelperOutputInterpretationV1 {
    Atomic(AtomicInterpretationOriginalV1),
    Mutation(Result<(), ZfsHelperError>),
}

impl HelperOutputInterpretationV1 {
    fn actual_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Atomic(original) => original.actual_failure(),
            Self::Mutation(result) => result.as_ref().err().map(resolve_helper_cause),
        }
    }
}

#[derive(Clone, Copy)]
enum InterpretationFailureV1 {
    Length,
    Digest,
    Count,
    Header,
    Members,
    Expected,
    Comparison,
}

/// Parks every completed interpretation before the next semantic frontier.
pub(super) struct AtomicInterpretationOriginalV1 {
    expected_length: Option<Result<usize, ZfsHelperError>>,
    digest: Option<Result<[u8; 32], ZfsHelperError>>,
    count: Option<Result<u16, ZfsHelperError>>,
    header: Option<Result<(), ZfsHelperError>>,
    member_guids: Option<Vec<u64>>,
    members_validation: Option<Result<(), ZfsHelperError>>,
    expected: Option<Result<ObjectDigest, ZfsHelperError>>,
    expected_digest: crate::lifecycle_atomic_snapshot::AtomicObservationDigestOriginalV1,
    comparison: Option<Result<(), ZfsHelperError>>,
    first: Option<InterpretationFailureV1>,
}

impl AtomicInterpretationOriginalV1 {
    pub(super) const fn new() -> Self {
        Self {
            expected_length: None,
            digest: None,
            count: None,
            header: None,
            member_guids: None,
            members_validation: None,
            expected: None,
            expected_digest: crate::lifecycle_atomic_snapshot::AtomicObservationDigestOriginalV1::new(),
            comparison: None,
            first: None,
        }
    }

    pub(super) fn run(
        &mut self,
        program: &crate::DormantAtomicDatasetSnapshotV1,
        output: &ZfsProcessOutput,
        retain_partial_members: bool,
    ) -> Result<ObservedAtomicSnapshotGroupV1, ()> {
        if self.expected_length.is_some() {
            return Err(());
        }
        self.expected_length = Some(42_usize.checked_add(program.member_count().saturating_mul(8))
            .ok_or(ZfsHelperError::PostconditionMismatch));
        let Some(Ok(expected_length)) = self.expected_length.as_ref() else {
            self.first = Some(InterpretationFailureV1::Length);
            return Err(());
        };
        // This is the existing first output predicate, before either slice.
        self.header = Some(if output.timed_out || !output.success
            || output.stdout.len() != *expected_length || !output.stderr.is_empty()
            || output.stdout.get(..8) != Some(b"AOSASO02".as_slice())
        {
            Err(ZfsHelperError::PostconditionMismatch)
        } else {
            Ok(())
        });
        if !matches!(self.header, Some(Ok(()))) {
            self.first = Some(InterpretationFailureV1::Header);
            return Err(());
        }
        self.digest = Some(output.stdout[8..40].try_into()
            .map_err(|_| ZfsHelperError::PostconditionMismatch));
        let Some(digest) = self.digest.as_ref().and_then(|result| result.as_ref().ok()).copied() else {
            self.first = Some(InterpretationFailureV1::Digest);
            return Err(());
        };
        self.count = Some(output.stdout[40..42].try_into()
            .map(u16::from_be_bytes).map_err(|_| ZfsHelperError::PostconditionMismatch));
        let Some(count) = self.count.as_ref().and_then(|result| result.as_ref().ok()).copied() else {
            self.first = Some(InterpretationFailureV1::Count);
            return Err(());
        };
        self.header = Some(if digest == [0; 32] || usize::from(count) != program.member_count() {
            Err(ZfsHelperError::PostconditionMismatch)
        } else {
            Ok(())
        });
        if !matches!(self.header, Some(Ok(()))) {
            self.first = Some(InterpretationFailureV1::Header);
            return Err(());
        }
        if retain_partial_members {
            self.member_guids = Some(Vec::new());
            self.members_validation = Some(Ok(()));
            let Some(member_guids) = self.member_guids.as_mut() else {
                std::process::abort();
            };
            // The selected collection remains in its destination even when a
            // later member fails; the ordinary fallible collect stays literal.
            for bytes in output.stdout[42..].chunks_exact(8) {
                let guid = bytes.try_into().map(u64::from_be_bytes)
                    .map_err(|_| ZfsHelperError::PostconditionMismatch)
                    .and_then(|guid| (guid != 0).then_some(guid)
                        .ok_or(ZfsHelperError::PostconditionMismatch));
                match guid {
                    Ok(guid) => member_guids.push(guid),
                    Err(cause) => {
                        self.members_validation = Some(Err(cause));
                        self.first = Some(InterpretationFailureV1::Members);
                        return Err(());
                    }
                }
            }
        } else {
            let members = output.stdout[42..].chunks_exact(8).map(|bytes| {
                let guid = u64::from_be_bytes(bytes.try_into()
                    .map_err(|_| ZfsHelperError::PostconditionMismatch)?);
                (guid != 0).then_some(guid).ok_or(ZfsHelperError::PostconditionMismatch)
            }).collect::<Result<Vec<_>, _>>();
            match members {
                Ok(members) => {
                    self.member_guids = Some(members);
                    self.members_validation = Some(Ok(()));
                }
                Err(cause) => {
                    self.members_validation = Some(Err(cause));
                    self.first = Some(InterpretationFailureV1::Members);
                    return Err(());
                }
            }
        }
        let Some(member_guids) = self.member_guids.as_ref() else {
            std::process::abort();
        };
        self.expected = Some(if retain_partial_members {
            self.expected_digest.calculate_retaining_v1(program, member_guids)
        } else {
            crate::lifecycle_atomic_snapshot::atomic_snapshot_observation_digest(program, member_guids)
        }.map_err(|_| ZfsHelperError::PostconditionMismatch));
        let Some(Ok(expected)) = self.expected.as_ref() else {
            self.first = Some(InterpretationFailureV1::Expected);
            return Err(());
        };
        self.comparison = Some(if expected.as_bytes() == &digest {
            Ok(())
        } else {
            Err(ZfsHelperError::PostconditionMismatch)
        });
        if !matches!(self.comparison, Some(Ok(()))) {
            self.first = Some(InterpretationFailureV1::Comparison);
            return Err(());
        }
        let Some(member_guids) = self.member_guids.take() else {
            std::process::abort();
        };
        Ok(ObservedAtomicSnapshotGroupV1 {
            digest: ObjectDigest::from_bytes(digest),
            member_guids,
        })
    }

    fn actual_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if matches!(self.first, Some(InterpretationFailureV1::Expected)) {
            if let Some(cause) = self.expected_digest.failure() {
                return Some(cause);
            }
        }
        self.failure().map(resolve_helper_cause)
    }

    pub(super) fn failure(&self) -> Option<&ZfsHelperError> {
        match self.first? {
            InterpretationFailureV1::Length => self.expected_length.as_ref()?.as_ref().err(),
            InterpretationFailureV1::Digest => self.digest.as_ref()?.as_ref().err(),
            InterpretationFailureV1::Count => self.count.as_ref()?.as_ref().err(),
            InterpretationFailureV1::Header => self.header.as_ref()?.as_ref().err(),
            InterpretationFailureV1::Members => self.members_validation.as_ref()?.as_ref().err(),
            InterpretationFailureV1::Expected => self.expected.as_ref()?.as_ref().err(),
            InterpretationFailureV1::Comparison => self.comparison.as_ref()?.as_ref().err(),
        }
    }

    pub(super) fn take_failure(&mut self) -> ZfsHelperError {
        let cause = match self.first.take() {
            Some(InterpretationFailureV1::Length) => self.expected_length.take().and_then(Result::err),
            Some(InterpretationFailureV1::Digest) => self.digest.take().and_then(Result::err),
            Some(InterpretationFailureV1::Count) => self.count.take().and_then(Result::err),
            Some(InterpretationFailureV1::Header) => self.header.take().and_then(Result::err),
            Some(InterpretationFailureV1::Members) => self.members_validation.take().and_then(Result::err),
            Some(InterpretationFailureV1::Expected) => self.expected.take().and_then(Result::err),
            Some(InterpretationFailureV1::Comparison) => self.comparison.take().and_then(Result::err),
            None => None,
        };
        match cause {
            Some(cause) => cause,
            None => std::process::abort(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn output(guid: u64, digest: ObjectDigest) -> ZfsProcessOutput {
        let mut stdout = Vec::from(b"AOSASO02".as_slice());
        stdout.extend_from_slice(digest.as_bytes());
        stdout.extend_from_slice(&1_u16.to_be_bytes());
        stdout.extend_from_slice(&guid.to_be_bytes());
        ZfsProcessOutput {
            stdout,
            stderr: Vec::new(),
            success: true,
            timed_out: false,
        }
    }

    #[test]
    fn rejected_digest_keeps_actual_guid_collection_and_raw_output() {
        let program = crate::lifecycle_atomic_snapshot::sample_atomic_snapshot_program_for_test();
        let output = output(41, ObjectDigest::from_bytes([93; 32]));
        let raw = output.stdout.as_ptr();
        let mut interpretation = AtomicInterpretationOriginalV1::new();

        assert!(interpretation.run(&program, &output, true).is_err());
        let members = interpretation.member_guids.as_ref().unwrap();
        assert_eq!(members, &[41]);
        let original_members = members.as_ptr();
        let first = interpretation.failure().unwrap() as *const ZfsHelperError;

        assert!(interpretation.run(&program, &output, true).is_err());
        assert_eq!(interpretation.member_guids.as_ref().unwrap().as_ptr(), original_members);
        assert_eq!(interpretation.failure().unwrap() as *const ZfsHelperError, first);
        assert_eq!(output.stdout.as_ptr(), raw);
        assert!(matches!(interpretation.comparison,
            Some(Err(ZfsHelperError::PostconditionMismatch))));
    }

    #[test]
    fn malformed_member_keeps_collection_destination_and_semantic_cause() {
        let program = crate::lifecycle_atomic_snapshot::sample_atomic_snapshot_program_for_test();
        let output = output(0, ObjectDigest::from_bytes([3; 32]));
        let mut interpretation = AtomicInterpretationOriginalV1::new();

        assert!(interpretation.run(&program, &output, true).is_err());

        assert!(interpretation.member_guids.as_ref().unwrap().is_empty());
        assert!(matches!(interpretation.members_validation,
            Some(Err(ZfsHelperError::PostconditionMismatch))));
        assert!(std::ptr::eq(
            interpretation.failure().unwrap(),
            interpretation.members_validation.as_ref().unwrap().as_ref().unwrap_err(),
        ));
    }

    #[test]
    fn shared_parser_moves_the_actual_successful_member_collection() {
        let program = crate::lifecycle_atomic_snapshot::sample_atomic_snapshot_program_for_test();
        let digest = crate::lifecycle_atomic_snapshot::atomic_snapshot_observation_digest(
            &program, &[41],
        ).unwrap();
        let output = output(41, digest);
        let mut interpretation = AtomicInterpretationOriginalV1::new();

        let observed = interpretation.run(&program, &output, true).unwrap();

        assert_eq!(observed.member_guids(), &[41]);
        assert_eq!(observed.digest(), digest);
        assert!(interpretation.member_guids.is_none());
        assert!(interpretation.failure().is_none());
        assert_eq!(parse_atomic_snapshot_output_v1(&program, &output).unwrap().digest(), digest);
    }

    #[test]
    fn reached_shape_overflow_has_the_exact_memory_dimension() {
        let cause = atomic_shape_v1(&[], &[], usize::MAX, 0).unwrap_err();

        assert!(matches!(cause, aos_sandbox_model::AccountingError::ArithmeticOverflow {
            dimension: aos_sandbox_model::ResourceDimension::MemoryBytes,
        }));
    }
}
