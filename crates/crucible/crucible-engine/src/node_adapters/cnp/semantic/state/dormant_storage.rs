//! Recognizes only inline, inactive common custody for owning-data observation.
//!
//! This check neither authenticates current authority nor permits activation.
//! Its fields are already inline in the process capsule. Every populated result,
//! readiness, activation, input or operation owner requires its own complete walk.

use super::SemanticRuntimeCustody;
use crate::node_contract::RuntimeError;

impl SemanticRuntimeCustody {
    pub(in crate::node_adapters::cnp::semantic) fn dormant_storage_data(
        &self,
    ) -> Result<(), RuntimeError> {
        let Self {
            installed_restoration,
            arm_attempt,
            ready,
            prepared_owner,
            activate_response,
            observe_sequence,
            activation_attempt,
            active,
            inputs,
            operations,
            watermark,
            observation,
            reclaimed,
            credit,
            quarantined: _,
        } = self;
        if installed_restoration.is_some()
            || arm_attempt.is_some()
            || ready.is_some()
            || prepared_owner.is_some()
            || activate_response.is_some()
            || observe_sequence.get() != 0
            || activation_attempt.is_some()
            || active.is_some()
            || !inputs.is_empty()
            || !operations.is_empty()
            || watermark.get() != 0
            || observation.is_some()
            || reclaimed.is_some()
        {
            return Err(RuntimeError::UnsupportedFacet);
        }
        // Empty BTreeMaps allocate no nodes. Credit is only a reserved byte
        // scalar; it is neither an owning bank nor a new allocation allowance.
        credit.inline_storage_data();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_node_format::U64;

    #[test]
    fn dormant_custody_keeps_reserved_credit_without_minting_readiness() {
        let mut state = SemanticRuntimeCustody::default();
        state.credit.reserve_bytes(4096, 4096).unwrap();
        state.quarantined = true;

        assert_eq!(state.dormant_storage_data(), Ok(()));
        assert_eq!(state.credit.retained_bytes(), 4096);
        assert!(state.ready.is_none());
        assert!(state.active.is_none());
        assert!(state.quarantined);
    }

    #[test]
    fn started_native_sequence_is_not_empty_dormant_custody() {
        let mut state = SemanticRuntimeCustody::default();
        state.observe_sequence = U64::new(1);
        assert_eq!(
            state.dormant_storage_data(),
            Err(RuntimeError::UnsupportedFacet)
        );
        state.observe_sequence = U64::new(0);
        state.watermark = U64::new(1);
        assert_eq!(
            state.dormant_storage_data(),
            Err(RuntimeError::UnsupportedFacet)
        );
    }
}
