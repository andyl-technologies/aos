//! Reuses the retained JSON stack without a second DOM or root tree copy.

use super::Native17Build;
use crate::ProviderError;
use crate::protocol_snapshot::owned11::{
    json_value::{HistoricalJsonBuildAttempt, ValidatedHistoricalJson},
    typed::{Ledger, invalid},
};
use crate::retained_metadata::MetadataObserver;
use serde_json::{Map, Value};
use std::collections::BTreeMap;

macro_rules! json_owner {
    ($type:ty, $root:expr, $read:ident, $borrow:ident, $take:ident) => {
        impl Native17Build for $type {
            type Attempt = HistoricalJsonBuildAttempt;

            fn preflight_data(
                input: &[u8],
                ledger: &mut Ledger<'_, '_, '_>,
            ) -> Result<(), ProviderError> {
                if $root && input.first() != Some(&b'{') {
                    return Err(invalid());
                }
                let plan =
                    ValidatedHistoricalJson::validate(input, ledger.rows.clone(), ledger.limits)?;
                ledger.native17_target_json_data(&plan)?;
                ledger.rows = plan.remaining_records();
                Ok(())
            }

            fn read_into_data(
                input: &[u8],
                ledger: &mut Ledger<'_, '_, '_>,
                attempt: &mut Self::Attempt,
            ) -> Result<(), ProviderError> {
                if $root && input.first() != Some(&b'{') {
                    attempt.interrupt_data();
                    return Err(invalid());
                }
                let plan = match ValidatedHistoricalJson::validate(
                    input,
                    ledger.rows.clone(),
                    ledger.limits,
                ) {
                    Ok(plan) => plan,
                    Err(error) => {
                        attempt.interrupt_data();
                        return Err(error);
                    }
                };
                if let Err(error) = ledger.native17_target_json_data(&plan) {
                    attempt.interrupt_data();
                    return Err(error);
                }
                ledger.rows = plan.remaining_records();
                plan.$read(attempt)
            }

            fn output_data(attempt: &Self::Attempt) -> Option<&Self> {
                attempt.$borrow()
            }

            fn take_output_data(attempt: &mut Self::Attempt) -> Option<Self> {
                attempt.$take()
            }

            fn observe_attempt_data(
                attempt: &Self::Attempt,
                observer: &mut MetadataObserver<'_>,
            ) -> Result<(), ProviderError> {
                attempt.observe_retained_metadata_data(observer)
            }

            fn observe_output_data(
                value: &Self,
                observer: &mut MetadataObserver<'_>,
            ) -> Result<(), ProviderError> {
                observer.observe(value)
            }
        }
    };
}

json_owner!(
    Value,
    false,
    reconstruct_into_data,
    completed_data,
    take_completed_data
);
json_owner!(
    Map<String, Value>,
    true,
    reconstruct_into_data,
    completed_object_data,
    take_completed_object_data
);
json_owner!(
    BTreeMap<String, Value>,
    true,
    reconstruct_extensions_into_data,
    completed_extensions_data,
    take_completed_extensions_data
);
