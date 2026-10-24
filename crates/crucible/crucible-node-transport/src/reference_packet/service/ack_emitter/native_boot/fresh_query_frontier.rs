//! Checks a fresh query against its real private purpose and completed frontier.
//!
//! The ephemeral result borrows the SAME original banks and stores only public
//! nonce/context/role commitments. It carries no grant or fresh completion
//! owner. The endpoint must retain its partial query owner and separately
//! admitted Prepare scope, then publish a real report/cache/prefix before a
//! completed query can route the next Prepare.

use super::*;
use crate::connection::{ExchangeRecord, OriginalNativeFreshFrontierData};
use crate::envelope::Envelope;
use crate::reference_packet::service::fresh_restore_allocation::*;
use base64::Engine as _;

/// Borrows nonce, ACK context, assigned query and completed Admit request/response digests.
pub(crate) type OriginalNativeFreshQueryCommitmentsData<'a> = (
    &'a [u8; 32],
    &'a [u8; 32],
    &'a [u8; 32],
    &'a [u8; 32],
    &'a [u8; 32],
);

pub(crate) struct OriginalNativeFreshQueryFrontierData<'a> {
    originals: OriginalNativeFreshFrontierData<'a>,
    nonce: [u8; 32],
    ack_context: [u8; 32],
    assigned_query: [u8; 32],
    completed_admit_request: [u8; 32],
    completed_admit_response: [u8; 32],
}

impl OriginalNativeFreshQueryFrontierData<'_> {
    /// Lends the exact public nonce, ACK context and original commitments.
    pub(crate) fn commitments_data(
        &self,
    ) -> Result<OriginalNativeFreshQueryCommitmentsData<'_>, ProviderError> {
        self.originals.authenticate_current_data()?;
        Ok((
            &self.nonce,
            &self.ack_context,
            &self.assigned_query,
            &self.completed_admit_request,
            &self.completed_admit_response,
        ))
    }

    /// Lends the completed actual Admit result's admission ID as data.
    pub(crate) fn admission_id_data(&self) -> Result<&str, ProviderError> {
        self.originals.admission_id_data()
    }
}

impl OriginalNativeReportStartupAllocation {
    /// Authenticates a query against this true Fresh purpose and actual originals.
    ///
    /// Baseline admission remains independently required and is explicitly
    /// unavailable in Native276. No body/report/receipt/cache/prefix is created
    /// by this immutable loan, even after that prerequisite becomes available.
    ///
    /// # Errors
    /// Refuses a changed purpose/origin, absent baseline, unadmitted fixed
    /// counter, intervening original, noncanonical bytes or mismatched nonce,
    /// completed-Admit commitment or native ACK context.
    pub(crate) fn authenticate_fresh_query_frontier_data<'a, S: ProviderStream>(
        &self,
        connection: &'a Connection<S>,
        query: &Envelope,
        first_response: u64,
        record: &'a ExchangeRecord,
    ) -> Result<OriginalNativeFreshQueryFrontierData<'a>, ProviderError> {
        self.authenticate_fresh_purpose(connection)?;
        self.authenticate_complete_native_baseline(connection)?;
        if Self::fresh_query_frontier_counter_scratch_data()
            > usize::try_from(self.row.declared_counter_scratch_bytes.get())
                .map_err(|_| refused())?
        {
            return Err(refused());
        }
        self.authenticate_query_header_data(connection, query)?;
        let token = connection.original_native_owned11_admission()?;
        let originals = token.identity.original_fresh_completed_admit_data(
            connection,
            &token.original,
            query,
            first_response,
            record,
        )?;
        {
            let boot = self.boot.try_borrow().map_err(|_| refused())?;
            boot.ensure_origin()?;
            originals.authenticate_owner_binding_data(
                &boot.data.source_birth,
                &boot.source_body,
                query,
            )?;
        }
        self.authenticate_fresh_purpose(connection)?;
        let nonce = self.fresh_restore_nonce_data(connection)?;
        let ack_context = self.fresh_restore_ack_context_digest_data(connection)?;
        let assigned_query = originals.assigned_query_digest_data()?;
        let completed_admit_request = originals.completed_admit_request_digest_data()?;
        let completed_admit_response = originals.completed_admit_response_digest_data()?;
        let values = query
            .extensions
            .get(PACKET_FRESH_RESTORE_ALLOCATION_QUERY)
            .and_then(serde_json::Value::as_object)
            .ok_or_else(refused)?;
        for (key, expected) in [
            ("nonce", &nonce),
            ("completed_admit_request", &completed_admit_request),
            ("completed_admit_response", &completed_admit_response),
        ] {
            authenticate_digest_data(values.get(key).ok_or_else(refused)?, expected)?;
        }
        self.authenticate_fresh_purpose(connection)?;
        originals.authenticate_current_data()?;
        Ok(OriginalNativeFreshQueryFrontierData {
            originals,
            nonce,
            ack_context,
            assigned_query,
            completed_admit_request,
            completed_admit_response,
        })
    }

    /// Names actual borrowed frontier and hashing/base64 work headers.
    pub(crate) const fn fresh_query_frontier_counter_scratch_data() -> usize {
        Connection::<crate::client::DeadlineStream>::original_fresh_frontier_counter_scratch_data()
            + std::mem::size_of::<OriginalNativeFreshQueryFrontierData<'static>>()
            + std::mem::size_of::<[u8; 43]>()
            + std::mem::size_of::<[[u8; 32]; 5]>()
            + std::mem::size_of::<[(&str, &[u8; 32]); 3]>()
            + std::mem::size_of::<OriginalNativeFreshQueryCommitmentsData<'static>>()
            // The owner comparison runs before nonce/role hashing and uses the
            // existing bounded object scanner, plus these explicit local views.
            + std::mem::size_of::<std::cell::Ref<'static, NativeAckBoot>>()
            + std::mem::size_of::<blake3::Hasher>()
            + std::mem::size_of::<blake3::Hash>()
            + std::mem::size_of::<[u8; 64]>()
            + 4 * std::mem::size_of::<&[u8]>()
            + std::mem::size_of::<&serde_json::Value>()
            + std::mem::size_of::<&Vec<serde_json::Value>>()
            + 8 * std::mem::size_of::<usize>()
    }
}

fn authenticate_digest_data(
    value: &serde_json::Value,
    expected: &[u8; 32],
) -> Result<(), ProviderError> {
    let mut encoded = [0u8; 43];
    let count = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode_slice(expected, &mut encoded)
        .map_err(|_| refused())?;
    if count != encoded.len() || value.as_str().map(str::as_bytes) != Some(encoded.as_slice()) {
        return Err(refused());
    }
    Ok(())
}

#[cfg(test)]
// crucible-lint: panic-shortcut: these data controls intentionally stop on invariant failures.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn original_digest_requires_exact_unpadded_url_encoding() {
        let expected = [0xa5; 32];
        let text = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(expected);
        authenticate_digest_data(&serde_json::Value::String(text.clone()), &expected).unwrap();
        for changed in [format!("{text}="), text.to_lowercase(), String::new()] {
            assert!(
                authenticate_digest_data(&serde_json::Value::String(changed), &expected).is_err()
            );
        }
        assert!(authenticate_digest_data(&serde_json::Value::String(text), &[0xa4; 32]).is_err());
        assert!(authenticate_digest_data(&serde_json::Value::Null, &expected).is_err());
    }
}
