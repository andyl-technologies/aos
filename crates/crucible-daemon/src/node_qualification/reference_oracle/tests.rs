//! Independent arithmetic and observation-mutation models, not native qualification.

// crucible-lint: allow panic-shortcut -- These reference oracle tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used)]

use crucible_node_contract::Position;

use super::*;

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn content<T: Serialize>(value: &T) -> (ContentRef, Bytes) {
    let bytes = canonical::canonical_json(&serde_json::to_value(value).unwrap()).unwrap();
    (
        canonical::content_ref(&bytes, "application/json").unwrap(),
        Bytes::new(bytes),
    )
}

fn fixture() -> (ReferenceOracleContract, Vec<ReferenceWindowObservation>) {
    let inputs = [vec![1, 2], vec![3], vec![255; 16]];
    let mut contract = ReferenceOracleContract {
        owner: id("model-owner"),
        incarnation: id("model-incarnation"),
        generation: U64::new(1),
        quantum_ps: U64::new(1000),
        host_budget_ns: U64::new(10_000_000),
        first_quantum: U64::new(1),
        first_time_ps: U64::new(0),
        initial_checksum: U64::new(0),
        maximum_windows: 3,
        maximum_input_bytes: 4096,
        expected_windows: Vec::new(),
    };
    let mut sum = 0u128;
    let modulus = 1u128 << 64;
    let mut observations = Vec::new();
    for (index, input) in inputs.into_iter().enumerate() {
        let window = id(&format!("model-window-{index}"));
        let batch = id(&format!("model-batch-{index}"));
        contract.expected_windows.push(ReferenceExpectedWindow {
            window: window.clone(),
            batch: batch.clone(),
            input: canonical::content_ref(&input, "application/octet-stream").unwrap(),
        });
        for byte in &input {
            sum = (sum * 257 + u128::from(*byte)) % modulus;
        }
        let grant = DeviceGrant {
            owner_id: contract.owner.clone(),
            incarnation_id: contract.incarnation.clone(),
            generation: contract.generation,
            window_id: window,
            input_batch_id: batch,
            quantum: U64::new(index as u64 + 1),
            start: Position::new(
                U64::new(index as u64 * 1000),
                U64::new(0),
                Phase::BoundaryControl,
            ),
            publication: Position::new(
                U64::new((index as u64 + 1) * 1000),
                U64::new(0),
                Phase::Publication,
            ),
            host_budget_ns: contract.host_budget_ns,
        };
        let output = DeviceOutput {
            bytes_processed: U64::new(input.len() as u64),
            checksum: U64::new(sum as u64),
        };
        let native = DeviceReceipt {
            grant: grant.clone(),
            output: output.clone(),
            measured_host_ns: U64::new(1234),
            application_parked: true,
        };
        let (receipt, receipt_bytes) = content(&native);
        let (payload, payload_bytes) = content(&output);
        observations.push(ReferenceWindowObservation {
            original_grant: grant,
            input: Bytes::new(input),
            receipt,
            receipt_bytes,
            payload,
            payload_bytes,
        });
    }
    (contract, observations)
}

#[test]
fn byte_limb_oracle_matches_wide_polynomial_and_known_native_contract_vectors() {
    let mut checksum = ByteLimbChecksum::new(0);
    checksum.push(1);
    checksum.push(2);
    assert_eq!(checksum.value(), 259);
    checksum.push(3);
    assert_eq!(checksum.value(), 66566);

    let mut state = 0x4d59_5df4_d0f3_3173u64;
    let mut wide = u128::from(checksum.value());
    let modulus = 1u128 << 64;
    for _ in 0..100_000 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let byte = (state & 255) as u8;
        wide = (wide * 257 + u128::from(byte)) % modulus;
        checksum.push(byte);
        assert_eq!(u128::from(checksum.value()), wide);
    }
}

#[test]
fn original_full_population_and_cumulative_checksum_model_are_verified() {
    let (contract, observations) = fixture();
    let result = verify_reference_windows(&contract, &observations).unwrap();
    assert_eq!(result.windows.get(), 3);
    assert_eq!(result.bytes_processed.get(), 19);
    assert_eq!(
        result.receipts,
        observations
            .iter()
            .map(|window| window.receipt.clone())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        result.payloads,
        observations
            .iter()
            .map(|window| window.payload.clone())
            .collect::<Vec<_>>()
    );
    let output: DeviceOutput =
        decode_original(observations[2].payload_bytes.as_slice(), 4096).unwrap();
    assert_eq!(result.checksum, output.checksum);

    assert!(verify_reference_windows(&contract, &observations[..2]).is_err());
    let mut reordered = observations.clone();
    reordered.swap(0, 1);
    assert!(verify_reference_windows(&contract, &reordered).is_err());
}

#[test]
fn changed_native_facts_fail_even_after_rehashing_changed_report_objects() {
    for mutation in 0..8 {
        let (contract, mut observations) = fixture();
        let original = &mut observations[1];
        let mut receipt: DeviceReceipt =
            decode_original(original.receipt_bytes.as_slice(), 65_536).unwrap();
        match mutation {
            0 => receipt.output.checksum = U64::new(receipt.output.checksum.get() + 1),
            1 => receipt.output.bytes_processed = U64::new(2),
            2 => receipt.measured_host_ns = U64::new(contract.host_budget_ns.get() + 1),
            3 => receipt.application_parked = false,
            4 => receipt.grant.incarnation_id = id("foreign-incarnation"),
            5 => receipt.grant.input_batch_id = id("foreign-original-batch"),
            6 => receipt.grant.publication.phase = Phase::Reaction,
            _ => receipt.grant.quantum = U64::new(9),
        }
        (original.receipt, original.receipt_bytes) = content(&receipt);
        (original.payload, original.payload_bytes) = content(&receipt.output);
        assert!(
            verify_reference_windows(&contract, &observations).is_err(),
            "accepted changed original native fact {mutation}"
        );
    }
}

#[test]
fn original_inputs_and_window_ids_cannot_be_repaired_by_consistent_fake_receipts() {
    let (contract, mut observations) = fixture();
    observations[0].input = Bytes::new(vec![4, 5]);
    assert!(verify_reference_windows(&contract, &observations).is_err());

    let (contract, mut observations) = fixture();
    let window = &mut observations[0];
    window.original_grant.window_id = id("replacement-window");
    let mut receipt: DeviceReceipt =
        decode_original(window.receipt_bytes.as_slice(), 65_536).unwrap();
    receipt.grant = window.original_grant.clone();
    (window.receipt, window.receipt_bytes) = content(&receipt);
    assert!(verify_reference_windows(&contract, &observations).is_err());
}

#[test]
fn time_and_quantum_overflow_refuse_while_checksum_modulus_is_explicit() {
    let (mut contract, observations) = fixture();
    contract.first_time_ps = U64::new(u64::MAX - 999);
    assert!(verify_reference_windows(&contract, &observations).is_err());

    let (mut contract, mut observations) = fixture();
    contract.first_quantum = U64::new(u64::MAX);
    observations[0].original_grant.quantum = contract.first_quantum;
    let mut receipt: DeviceReceipt =
        decode_original(observations[0].receipt_bytes.as_slice(), 65_536).unwrap();
    receipt.grant = observations[0].original_grant.clone();
    (observations[0].receipt, observations[0].receipt_bytes) = content(&receipt);
    assert!(verify_reference_windows(&contract, &observations).is_err());
}
