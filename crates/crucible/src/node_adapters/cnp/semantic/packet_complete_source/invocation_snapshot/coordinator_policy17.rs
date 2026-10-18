//! Retains the explicit original coordinator17 lifetime policy before birth.
//!
//! This fixed scalar selection owns no heap bank and issues no operational
//! permission. Each real initial Runtime separately admits its complete append
//! bank. Fresh Worlds inherit the exact signed original ceiling and counters.

use super::*;

/// Retains a failed policy attempt distinctly from an unselected old Source.
#[derive(Clone, Copy)]
pub(in crate::node_adapters::cnp::semantic::packet_complete_source) enum CoordinatorPolicy17 {
    /// Retains an unsuccessful once attempt without a usable policy.
    Attempted,
    /// Retains the actual selected lifetime ceiling without issuing credit.
    Bound {
        /// Bounds cumulative operational and semantic append identities.
        maximum_records: usize,
    },
}

impl PacketCompleteSemanticSource {
    /// Binds the selected coordinator17 lifetime ceiling before native birth.
    ///
    /// The complete strict17 declaration must already be fixed. A failed policy
    /// attempt poisons this same occurrence; a duplicate cannot replace the
    /// original ceiling. This DATA selection authorizes no native allocation.
    ///
    /// # Errors
    /// Refuses foreign origin, another declaration, repeated or late binding,
    /// a ceiling unable to fund the two genuine genesis rows, or an integer
    /// unrepresentable by the portable cumulative sequence type.
    pub fn bind_original_restored_settled_coordinator_policy17(
        &mut self,
        maximum_records: usize,
    ) -> Result<(), RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        if self.original_coordinator_policy17.is_some() {
            return Err(RuntimeError::DuplicateOperation);
        }
        if !self.is_original_restored_settled_capture_declaration_data()? {
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
        self.original_coordinator_policy17 = Some(CoordinatorPolicy17::Attempted);
        if maximum_records < 2 || u64::try_from(maximum_records).is_err() {
            return Err(RuntimeError::ResourceLimit);
        }
        self.storage_origin_with_error::<RuntimeError>()?;
        self.original_coordinator_policy17 = Some(CoordinatorPolicy17::Bound { maximum_records });
        Ok(())
    }

    /// Borrows the actual explicit policy without granting credit or a new bank.
    ///
    /// Old unselected Sources return `None`. A selected17 Source cannot replace
    /// a missing/failed policy with a default, native receive limit or caller
    /// ordinal. Full declaration correspondence remains mandatory on every read.
    ///
    /// # Errors
    /// Refuses foreign origin, a changed declaration, an unbound/failed17 policy
    /// or policy state attached to an older declaration.
    pub fn original_restored_settled_coordinator_policy17_data(
        &self,
    ) -> Result<Option<usize>, RuntimeError> {
        let selected = self.is_original_restored_settled_capture_declaration_data()?;
        match (selected, self.original_coordinator_policy17) {
            (false, None) => Ok(None),
            (true, Some(CoordinatorPolicy17::Bound { maximum_records }))
                if maximum_records >= 2 =>
            {
                Ok(Some(maximum_records))
            }
            _ => Err(RuntimeError::UnsupportedFacet),
        }
    }

    /// Names the defining borrowed selection, scalar and result views.
    pub fn original_restored_settled_coordinator_policy17_counter_scratch_data() -> usize {
        Self::original_restored_settled_capture_declaration_counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<&mut Self>()
            + size_of::<Option<CoordinatorPolicy17>>()
            + size_of::<Option<usize>>()
            + size_of::<Result<Option<usize>, RuntimeError>>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<usize>()
            + size_of::<bool>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_adapters::cnp::semantic::packet_complete_source::tests as fixture;

    #[test]
    fn old_actual_sources_do_not_infer_policy_or_promote_mutated_policy_state() {
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
                    .original_restored_settled_coordinator_policy17_data()
                    .unwrap(),
                None
            );
            assert!(
                source
                    .bind_original_restored_settled_coordinator_policy17(256)
                    .is_err()
            );
            assert!(source.original_coordinator_policy17.is_none());
            source.original_coordinator_policy17 = Some(CoordinatorPolicy17::Bound {
                maximum_records: 256,
            });
            assert!(
                source
                    .original_restored_settled_coordinator_policy17_data()
                    .is_err()
            );
            assert!(source.capture_banks.get_mut().is_none());
            assert!(source.ack_peer_birth.get_mut().is_none());
            assert!(source.authenticate_current_native().is_err());
        }
    }
}
