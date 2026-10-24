//! Retains the explicit import18 coordinator lifetime policy before Source birth.
//!
//! This is a separate scalar once occurrence from the unchanged policy17.
//! A genuine installed SourceSignedImport18 declaration chooses this mechanism;
//! format advertisements and archived Source families cannot select it. Runtime
//! append banks, inherited lifetime equality and native permission are separate.

use super::*;

/// Distinguishes a failed selected18 binding from an unselected legacy Source.
#[derive(Clone, Copy)]
pub(in crate::node_adapters::cnp::semantic::packet_complete_source) enum CoordinatorPolicy18 {
    /// Preserves the unsuccessful once occurrence without a usable ceiling.
    Attempted,
    /// Retains the actual installed scalar, without a bank or new credit.
    Bound { maximum_records: usize },
}

impl PacketCompleteSemanticSource {
    /// Binds the explicit import18 coordinator lifetime ceiling before birth.
    ///
    /// The actual installed baseline supplies this scalar after its full Launch5
    /// declaration has been authenticated. A valid prebirth attempt is spent
    /// before scalar validation; a failed occurrence cannot be renewed or reset.
    /// No policy17 marker, native limit or current World is inferred or changed.
    ///
    /// # Errors
    /// Refuses foreign origin, another or failed declaration, duplicate/late or
    /// already prepared ownership, an incompatible policy17 occurrence, fewer
    /// than two genesis rows, or a ceiling outside the portable u64 range.
    pub fn bind_original_restored_settled_coordinator_policy18(
        &mut self,
        maximum_records: usize,
    ) -> Result<(), RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        if self.original_coordinator_policy18.is_some() {
            return Err(RuntimeError::DuplicateOperation);
        }
        if !self.is_original_native_import18_declaration_data()?
            || self.original_coordinator_policy17.is_some()
        {
            return Err(RuntimeError::UnsupportedFacet);
        }
        if self.complete_bytes_launch_reserved.get()
            || self.registry_retention_attempted.get()
            || self.registry_retention_failed.get()
            || self.capture_banks.get_mut().is_some()
            || self.capture_execution.get_mut().is_some()
            || self.registry_capture.get_mut().is_some()
            || self.original_extension_registry.get_mut().is_some()
            || self.preconstruction.get_mut().is_some()
            || self.ack_birth_attempted
            || self.ack_peer_birth.get_mut().is_some()
            || self.ack_peer_association.get_mut().is_some()
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        let unbound = match &self.original {
            CompletePacketOriginal::Producer(source) => {
                source.complete_preparation_unbound_with_error::<RuntimeError>()?
            }
            CompletePacketOriginal::Reactive(source) => {
                source.complete_preparation_unbound_with_error::<RuntimeError>()?
            }
        };
        if !unbound {
            return Err(RuntimeError::OutstandingObligations);
        }

        self.original_coordinator_policy18 = Some(CoordinatorPolicy18::Attempted);
        if maximum_records < 2 || u64::try_from(maximum_records).is_err() {
            return Err(RuntimeError::ResourceLimit);
        }

        self.storage_origin_with_error::<RuntimeError>()?;
        self.original_coordinator_policy18 = Some(CoordinatorPolicy18::Bound { maximum_records });
        Ok(())
    }

    /// Borrows the actual import18 lifetime scalar without granting append credit.
    ///
    /// Unselected legacy Sources return None. A genuine selected18 declaration
    /// requires its own successful binding; neither a failed/missing policy nor
    /// another edition's policy can supply a default. Exact archived/current
    /// lifetime equality and authenticated cumulative counters are later joins.
    ///
    /// # Errors
    /// Refuses foreign origin, a failed declaration/policy, selected18 without a
    /// successful binding, or policy18 state attached to another mechanism.
    pub fn original_restored_settled_coordinator_policy18_data(
        &self,
    ) -> Result<Option<usize>, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        let selected = self.is_original_native_import18_declaration_data()?;
        let policy = match (selected, self.original_coordinator_policy18) {
            (false, None) => None,
            (true, Some(CoordinatorPolicy18::Bound { maximum_records }))
                if maximum_records >= 2 && self.original_coordinator_policy17.is_none() =>
            {
                Some(maximum_records)
            }
            _ => return Err(RuntimeError::UnsupportedFacet),
        };
        self.storage_origin_with_error::<RuntimeError>()?;
        Ok(policy)
    }

    /// Names the real cached declaration, scalar, once and origin controls.
    pub fn original_restored_settled_coordinator_policy18_counter_scratch_data() -> usize {
        Self::native_import18_declaration_counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<&mut Self>()
            + size_of::<CoordinatorPolicy18>()
            + size_of::<Option<CoordinatorPolicy18>>()
            + size_of::<Option<CoordinatorPolicy17>>()
            + size_of::<Option<usize>>()
            + size_of::<Result<Option<usize>, RuntimeError>>()
            + size_of::<Result<bool, RuntimeError>>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<Result<u64, std::num::TryFromIntError>>()
            + size_of::<usize>()
            + size_of::<bool>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_adapters::cnp::semantic::packet_complete_source::tests as fixture;

    #[test]
    fn legacy_sources_cannot_select18_or_recover_a_failed_policy_occurrence() {
        for reactive in [false, true] {
            let coordinator = fixture::coordinator();
            let mut source = if reactive {
                PacketCompleteSemanticSource::new_reactive_for_collecting_world(
                    fixture::installation(&coordinator, 1),
                    fixture::reactive(&coordinator, 1),
                    coordinator,
                    fixture::storage_selection(),
                )
                .unwrap()
            } else {
                PacketCompleteSemanticSource::new_producer_for_collecting_world(
                    fixture::installation(&coordinator, 0),
                    fixture::producer(),
                    coordinator,
                    fixture::storage_selection(),
                )
                .unwrap()
            };

            assert_eq!(
                source
                    .original_restored_settled_coordinator_policy18_data()
                    .unwrap(),
                None
            );
            assert!(
                source
                    .bind_original_restored_settled_coordinator_policy18(256)
                    .is_err()
            );
            assert!(source.original_coordinator_policy18.is_none());
            assert!(source.original_coordinator_policy17.is_none());

            // A failed once value is not a default and cannot be retried. This
            // negative DATA mutation creates no selected declaration or grant.
            source.original_coordinator_policy18 = Some(CoordinatorPolicy18::Attempted);
            assert!(
                source
                    .original_restored_settled_coordinator_policy18_data()
                    .is_err()
            );
            assert!(
                source
                    .bind_original_restored_settled_coordinator_policy18(256)
                    .is_err()
            );
            assert!(matches!(
                source.original_coordinator_policy18,
                Some(CoordinatorPolicy18::Attempted)
            ));
            assert!(source.original_coordinator_policy17.is_none());
            assert!(source.capture_banks.get_mut().is_none());
            assert!(source.ack_peer_birth.get_mut().is_none());
        }
    }
}
