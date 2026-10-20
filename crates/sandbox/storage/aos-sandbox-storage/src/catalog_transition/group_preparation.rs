//! Retains actual grouped transition preparation before later encoding failures.
//!
//! Ordinary and selected paths share the existing checks and canonical codecs.
//! The genuine State codec context prepays reached non-JSON program buffers.

use super::*;
use super::preparation::PreparationFailureV1;
use super::provider::group_transition_payload;

#[derive(Clone, Copy)]
enum GroupFailure {
    Validation,
    ProgramPayment,
    Program,
    DigestPayment,
    Digest,
    PhysicalPayment,
    Prepared,
}

pub(crate) struct AtomicGroupPreparationOriginalV1 {
    inner: CatalogTransitionPreparationOriginalV1,
    physical: super::physical_preparation::AtomicPhysicalApplicationOriginalV1,
    canonical_program: Option<Result<Vec<u8>, StorageStateError>>,
    program_encoding: crate::lifecycle_atomic_snapshot::AtomicProgramEncodingOriginalV1,
    observation_digest: Option<Result<ObjectDigest, aos_sandbox_controller_domain::lifecycle::LifecyclePhase6ErrorV1>>,
    digest_encoding: crate::lifecycle_atomic_snapshot::AtomicObservationDigestOriginalV1,
    validation: Option<Result<(), StorageStateError>>,
    first: Option<GroupFailure>,
}

impl AtomicGroupPreparationOriginalV1 {
    pub(crate) const fn new() -> Self {
        Self {
            inner: CatalogTransitionPreparationOriginalV1::new(),
            physical: super::physical_preparation::AtomicPhysicalApplicationOriginalV1::new(),
            canonical_program: None,
            program_encoding: crate::lifecycle_atomic_snapshot::AtomicProgramEncodingOriginalV1::new(),
            observation_digest: None,
            digest_encoding: crate::lifecycle_atomic_snapshot::AtomicObservationDigestOriginalV1::new(),
            validation: None,
            first: None,
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            GroupFailure::Validation => self.validation.as_ref()?.as_ref().err()
                .map(|cause| cause as &dyn std::error::Error),
            GroupFailure::Program => self.program_encoding.failure()
                .map(|cause| cause as &dyn std::error::Error)
                .or_else(|| self.canonical_program.as_ref()?.as_ref().err()
                    .map(|cause| cause as &dyn std::error::Error)),
            GroupFailure::Digest => self.digest_encoding.failure()
                .map(|cause| cause as &dyn std::error::Error)
                .or_else(|| self.observation_digest.as_ref()?.as_ref().err()
                    .map(|cause| cause as &dyn std::error::Error)),
            GroupFailure::Prepared => self.physical.actual_failure()
                .or_else(|| self.inner.failure().map(|cause| cause as &dyn std::error::Error)),
            GroupFailure::ProgramPayment | GroupFailure::DigestPayment | GroupFailure::PhysicalPayment => None,
        }
    }

    fn take_failure(&mut self) -> Option<StorageStateError> {
        match self.first? {
            GroupFailure::Validation => self.validation.take().and_then(Result::err),
            GroupFailure::Program => self.canonical_program.take().and_then(Result::err),
            GroupFailure::Digest => self.observation_digest.take().and_then(Result::err)
                .map(|_| StorageStateError::InvalidValue),
            GroupFailure::Prepared => self.inner.take_failure(),
            GroupFailure::ProgramPayment | GroupFailure::DigestPayment | GroupFailure::PhysicalPayment => None,
        }
    }
}

impl StorageCatalogTransitionProvider {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_atomic_group_transition_receiving_v1(
        &self,
        program: &crate::DormantAtomicDatasetSnapshotV1,
        request_digest: ObjectDigest,
        observation: ObjectDigest,
        member_guids: &[u64],
        key_id: [u8; 16],
        secret: &[u8; 32],
        mut receiving: Option<&mut crate::state::encoding::StateEncodingContextV1<'_, '_, '_>>,
        original: &mut AtomicGroupPreparationOriginalV1,
    ) -> Result<PreparedCatalogTransition, StorageStateError> {
        let selected = receiving.is_some();
        let result = (|| {
            let reservation = self.reservations.get(&program.operation())
                .ok_or(StorageStateError::InvalidTransition)?;
            original.first = Some(GroupFailure::Validation);
            original.validation = Some(if self.transitions.contains_key(&program.operation())
                || reservation.payload.group_program != Some(*program.commitment().as_bytes())
                || reservation.payload.request_digest != *request_digest.as_bytes()
            {
                Err(StorageStateError::InvalidTransition)
            } else {
                Ok(())
            });
            if !matches!(original.validation, Some(Ok(()))) {
                return Err(StorageStateError::Receiving);
            }
            if let Some(receiving) = receiving.as_deref_mut() {
                original.first = Some(GroupFailure::ProgramPayment);
                receiving.reserve_owned_capacity_v1(
                    crate::state::program_capacity_v1(program),
                    // Group8 + named physical/canonical owners + preparation9 + both
                    // program/digest encoder5; context6/codec5/archives4 and
                    // four existing plus named physical call/result controls.
                    3 * (8 + super::PHYSICAL_APPLICATION_OWNED_CELLS + 9 + 5 + 5) + 6 + 5 + 4 + 4
                        + super::PHYSICAL_APPLICATION_CALL_CELLS,
                )?;
            }
            original.first = Some(GroupFailure::Program);
            let canonical_program = program.canonical_bytes_retaining_v1(
                &mut original.program_encoding,
            );
            if !selected {
                original.program_encoding =
                    crate::lifecycle_atomic_snapshot::AtomicProgramEncodingOriginalV1::new();
            }
            original.canonical_program = Some(canonical_program
                .map_err(|_| StorageStateError::InvalidValue));
            let Some(Ok(canonical_program)) = original.canonical_program.as_ref() else {
                return Err(StorageStateError::Receiving);
            };
            let catalog_mismatch = reservation.payload.catalog_bytes_digest
                != digest_bytes(canonical_program);
            if !selected {
                // Each lazy-boolean operand has its own temporary scope. The
                // old program buffer ended before the next head/digest test.
                drop(original.canonical_program.take());
            }
            original.first = Some(GroupFailure::Validation);
            original.validation = Some(if catalog_mismatch
                || self.head_binding() != Some(reservation.predecessor.binding)
            {
                Err(StorageStateError::InvalidTransition)
            } else {
                Ok(())
            });
            if !matches!(original.validation, Some(Ok(()))) {
                return Err(StorageStateError::Receiving);
            }
            if let Some(receiving) = receiving.as_deref_mut() {
                original.first = Some(GroupFailure::DigestPayment);
                receiving.reserve_owned_shape_v1(
                    crate::lifecycle_atomic_snapshot::observation_digest_receiving_shape_v1(
                        program.member_count(),
                    ),
                )?;
            }
            original.first = Some(GroupFailure::Digest);
            original.observation_digest = Some(if selected {
                original.digest_encoding.calculate_retaining_v1(program, member_guids)
            } else {
                crate::lifecycle_atomic_snapshot::atomic_snapshot_observation_digest(
                    program, member_guids,
                )
            });
            let Some(Ok(actual_observation)) = original.observation_digest.as_ref() else {
                return Err(StorageStateError::Receiving);
            };
            original.first = Some(GroupFailure::Validation);
            original.validation = Some(if *actual_observation != observation {
                Err(StorageStateError::InvalidTransition)
            } else {
                Ok(())
            });
            if !matches!(original.validation, Some(Ok(()))) {
                return Err(StorageStateError::Receiving);
            }

            if let Some(receiving) = receiving.as_deref_mut() {
                original.first = Some(GroupFailure::PhysicalPayment);
                receiving.reserve_owned_shape_v1(
                    super::physical_preparation::application_shape_v1(
                        &reservation.predecessor, program,
                    ),
                )?;
            }
            original.first = Some(GroupFailure::Prepared);
            let inner = &mut original.inner;
            inner.first = Some(PreparationFailureV1::ResultState);
            inner.result_state = Some(match receiving.as_deref_mut() {
                Some(receiving) => original.physical.apply(
                    &reservation.predecessor, program, member_guids, receiving,
                ),
                None => reservation.predecessor.apply_atomic_snapshot_group(program, member_guids),
            });
            let Some(Ok(result_state)) = inner.result_state.as_ref() else {
                return Err(StorageStateError::Receiving);
            };
            inner.first = Some(PreparationFailureV1::Transition);
            inner.transition = Some(Ok(group_transition_payload(
                program, &reservation.predecessor, result_state, observation, member_guids,
            )));
            let Some(Ok(transition)) = inner.transition.as_ref() else {
                return Err(StorageStateError::Receiving);
            };
            inner.first = Some(PreparationFailureV1::TransitionBytes);
            inner.transition_bytes = Some(encode_transition_payload_receiving_v1(
                transition, key_id, secret, receiving.as_deref_mut(),
            ));
            if !matches!(inner.transition_bytes, Some(Ok(_))) {
                return Err(StorageStateError::Receiving);
            }
            inner.first = Some(PreparationFailureV1::Digest);
            inner.digest = Some(transition_digest_receiving_v1(
                transition, receiving.as_deref_mut(),
            ));
            let Some(Ok(digest)) = inner.digest.as_ref() else {
                return Err(StorageStateError::Receiving);
            };
            inner.head_payload = Some(HeadPayload {
                binding: result_state.binding.into(),
                operation_id: Some(program.operation()),
                transition_digest: Some(*digest.as_bytes()),
                genesis_state: None,
            });
            let Some(head_payload) = inner.head_payload.as_ref() else {
                std::process::abort();
            };
            inner.first = Some(PreparationFailureV1::HeadBytes);
            inner.head_bytes = Some(encode_head_payload_receiving_v1(
                head_payload, key_id, secret, receiving,
            ));
            let Some(Ok(head_bytes)) = inner.head_bytes.as_ref() else {
                return Err(StorageStateError::Receiving);
            };
            inner.first = Some(PreparationFailureV1::HeadBound);
            inner.head_bound = Some(if head_bytes.len() > MAXIMUM_HEAD_BYTES {
                Err(StorageStateError::InvalidValue)
            } else {
                Ok(())
            });
            if !matches!(inner.head_bound, Some(Ok(()))) {
                return Err(StorageStateError::Receiving);
            }
            let Some(Ok(result_state)) = inner.result_state.take() else {
                std::process::abort();
            };
            let Some(Ok(transition)) = inner.transition.take() else {
                std::process::abort();
            };
            let Some(Ok(transition_bytes)) = inner.transition_bytes.take() else {
                std::process::abort();
            };
            let Some(Ok(head_bytes)) = inner.head_bytes.take() else {
                std::process::abort();
            };
            inner.first = None;
            original.first = None;
            Ok(PreparedCatalogTransition {
                operation_id: program.operation(), snapshot_metadata: None,
                transition, transition_bytes, head_bytes, result_state,
            })
        })();
        result.map_err(|cause| if selected {
            cause
        } else {
            original.take_failure().unwrap_or(cause)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrong_group_observation_keeps_validation_and_preserves_provider_head() {
        let source_catalog = super::super::tests::catalog(7, "tank/aos/project/work");
        let directory = tempfile::tempdir().unwrap();
        let (mut journal, _) = aos_sandbox_controller_domain::Journal::open(
            directory.path().join("group-catalog.journal"),
            aos_sandbox_controller_domain::JournalLimits::default(),
        ).unwrap();
        let key_id = [71; 16];
        let secret = [72; 32];
        let request = ObjectDigest::from_bytes([73; 32]);
        let empty = StorageCatalogTransitionProvider::load(&journal, key_id, &secret).unwrap();
        let bootstrap = empty.prepare_bootstrap(
            6, std::slice::from_ref(&source_catalog), key_id, &secret,
        ).unwrap();
        journal.commit(&aos_sandbox_controller_domain::JournalTransaction::new(
            [74; 16], vec![bootstrap.record()],
        ).unwrap()).unwrap();
        let mut provider = StorageCatalogTransitionProvider::load(&journal, key_id, &secret).unwrap();
        let head = provider.head_binding().unwrap();
        let program = crate::lifecycle_atomic_snapshot::atomic_snapshot_program_for_catalog_test(
            6, provider.genesis_binding().unwrap().digest(), head.digest(),
            "tank/aos/project", 15,
        );
        let reservation = provider.reserve_atomic_group(&program, request, key_id, &secret).unwrap();
        provider.install_reservation(reservation);
        let mut original = AtomicGroupPreparationOriginalV1::new();

        let result = provider.prepare_atomic_group_transition_receiving_v1(
            &program, request, ObjectDigest::from_bytes([75; 32]), &[76], key_id, &secret,
            None, &mut original,
        );

        // The ordinary adapter moves the exact error out of its capture.
        assert!(matches!(result, Err(StorageStateError::InvalidTransition)));
        assert!(original.failure().is_none());
        assert!(original.inner.result_state.is_none());
        assert!(original.canonical_program.is_none());
        assert_eq!(provider.head_binding(), Some(head));
        assert!(!provider.transitions.contains_key(&program.operation()));
    }
}
