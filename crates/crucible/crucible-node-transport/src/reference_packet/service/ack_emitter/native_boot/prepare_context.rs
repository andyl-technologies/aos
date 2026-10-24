//! Authenticates the privately derived Prepare context with one canonical bank.
//!
//! The actual caller constructs this context immediately from the validated
//! request's canonical bytes, actual boot/Hello registrations and input roster.
//! This helper grants no native authority and accepts no request-binding labels
//! as a substitute for that construction. Public proof-data helpers retain their
//! independent validation and serialization behavior.

use super::*;

pub(super) fn authenticate_derived_context_data(
    key: &[u8; 32],
    context: &PacketCompleteRestorePrepareContext,
    proof: &PacketCompleteRestoreTransferProof,
) -> Result<Vec<u8>, ProviderError> {
    let PacketCompleteRestorePrepareContext {
        schema,
        algorithm,
        source_birth,
        kernel_binding,
        policy_binding,
        host_registration,
        native_registration,
        hello_request,
        hello_response,
        assigned_prepare,
        prepare_request,
        input_roster,
    } = context;
    let PacketCompleteRestoreTransferProof {
        schema: proof_schema,
        algorithm: proof_algorithm,
        context_digest,
        mac,
    } = proof;
    if schema != "source-owned.packet-complete-restore-prepare-context/12"
        || algorithm != PACKET_COMPLETE_RESTORE_ALGORITHM
        || proof_schema != PacketCompleteRestoreTransferPhase::Prepare.proof_extension()
        || proof_algorithm != PACKET_COMPLETE_RESTORE_ALGORITHM
        || [
            source_birth,
            kernel_binding,
            policy_binding,
            host_registration,
            native_registration,
            hello_request,
            hello_response,
            assigned_prepare,
            prepare_request,
            input_roster,
            context_digest,
            mac,
        ]
        .iter()
        .any(|digest| digest.as_slice().len() != blake3::OUT_LEN)
    {
        return Err(refused());
    }

    // Every serialized field now has an exact fixed string/digest extent. The
    // count checks that closed shape before constructing its DOM/canonical bank.
    crate::connection::serialized_credit(context, MAXIMUM_COMPLETE_RESTORE_TRANSFER_CONTEXT_BYTES)?;
    let value = serde_json::to_value(context).map_err(ContractError::from)?;
    let bytes = canonical::canonical_json(&value)?;
    if bytes.len() > MAXIMUM_COMPLETE_RESTORE_TRANSFER_CONTEXT_BYTES {
        return Err(refused());
    }
    let expected_context = blake3::hash(&bytes);
    let derived = blake3::derive_key("source-owned.packet-complete-restore-prepare-key/12", key);
    let expected_mac = blake3::keyed_hash(&derived, &bytes);
    if expected_context != *context_digest.as_slice() || expected_mac != *mac.as_slice() {
        return Err(refused());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn context() -> PacketCompleteRestorePrepareContext {
        PacketCompleteRestorePrepareContext {
            schema: "source-owned.packet-complete-restore-prepare-context/12".into(),
            algorithm: PACKET_COMPLETE_RESTORE_ALGORITHM.into(),
            source_birth: Bytes::new(vec![1; 32]),
            kernel_binding: Bytes::new(vec![2; 32]),
            policy_binding: Bytes::new(vec![3; 32]),
            host_registration: Bytes::new(vec![4; 32]),
            native_registration: Bytes::new(vec![5; 32]),
            hello_request: Bytes::new(vec![6; 32]),
            hello_response: Bytes::new(vec![7; 32]),
            assigned_prepare: Bytes::new(vec![8; 32]),
            prepare_request: Bytes::new(vec![9; 32]),
            input_roster: Bytes::new(vec![10; 32]),
        }
    }

    #[test]
    fn privately_derived_context_matches_normative_proof_and_canonical_bytes() -> TestResult {
        let context = context();
        let key = [31; 32];
        let proof = complete_restore_prepare_proof_data(&key, &context)?;
        verify_complete_restore_prepare_proof_data(&key, &context, &proof)?;
        let actual = authenticate_derived_context_data(&key, &context, &proof)?;

        assert_eq!(
            actual,
            canonical::canonical_json(&serde_json::to_value(&context)?)?
        );
        assert!(authenticate_derived_context_data(&[32; 32], &context, &proof).is_err());
        Ok(())
    }

    #[test]
    fn every_context_binding_and_proof_grammar_remains_authenticated() -> TestResult {
        let key = [31; 32];
        let proof = complete_restore_prepare_proof_data(&key, &context())?;
        for index in 0..10 {
            let mut changed = context();
            let fields = [
                &mut changed.source_birth,
                &mut changed.kernel_binding,
                &mut changed.policy_binding,
                &mut changed.host_registration,
                &mut changed.native_registration,
                &mut changed.hello_request,
                &mut changed.hello_response,
                &mut changed.assigned_prepare,
                &mut changed.prepare_request,
                &mut changed.input_roster,
            ];
            *fields.into_iter().nth(index).ok_or("fixed digest field")? = Bytes::new(vec![63; 32]);
            assert!(authenticate_derived_context_data(&key, &changed, &proof).is_err());
        }
        for changed in [
            PacketCompleteRestoreTransferProof {
                schema: "foreign".into(),
                ..complete_restore_prepare_proof_data(&key, &context())?
            },
            PacketCompleteRestoreTransferProof {
                algorithm: "foreign".into(),
                ..complete_restore_prepare_proof_data(&key, &context())?
            },
            PacketCompleteRestoreTransferProof {
                context_digest: Bytes::new(vec![1; 31]),
                ..complete_restore_prepare_proof_data(&key, &context())?
            },
            PacketCompleteRestoreTransferProof {
                mac: Bytes::new(vec![1; 32]),
                ..complete_restore_prepare_proof_data(&key, &context())?
            },
        ] {
            assert!(authenticate_derived_context_data(&key, &context(), &changed).is_err());
        }
        Ok(())
    }
}
