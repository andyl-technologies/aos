//! UNRUN inert signed-history vectors, never a genuine startup or floor owner.

use ed25519_dalek::{Signer as _, SigningKey};

use super::*;
use crate::journal::JournalRecord;
use super::super::genesis::{credential_contract, empty_ledger_anchor};
use crate::tpm_nv_custody::canonical_nv_name_v1;

pub(crate) struct Fixture {
    pub(crate) genesis: DeploymentGenesisV1,
    pub(crate) exact: Vec<u8>,
    pub(crate) signer: SigningKey,
    scope: [u8; 32],
}

impl Fixture {
    pub(crate) fn new() -> Self {
        let signer = SigningKey::from_bytes(&[1; 32]);
        let provisioner = SigningKey::from_bytes(&[2; 32]);
        let mut salt = [3; 34];
        salt[..2].copy_from_slice(&0x000b_u16.to_be_bytes());
        let genesis = DeploymentGenesisV1 {
            node: [4; 16], deployment: [5; 16], signer: signer.verifying_key().to_bytes(),
            nv_name: canonical_nv_name_v1(NvCustodyEndpointV1::RuntimeDeployment),
            salt_name: salt, empty_ledger_anchor: empty_ledger_anchor(), publisher_profile: [6; 32],
            nspawn_digest: [7; 32], root_digest: [8; 32], supervisor_filter: [9; 32],
            payload_filter: [10; 32], mac_policy: [11; 32], credential_contract: credential_contract(),
            uid_start: 65_536, uid_count: 65_536,
        };
        let mut exact = genesis.encode().unwrap().to_vec();
        let message = [b"aos.runtime-deployment.genesis.v1\0".as_slice(), &exact].concat();
        exact.extend_from_slice(&provisioner.sign(&message).to_bytes());
        let scope = Sha256::new()
            .chain_update(b"aos.sandbox.tpm-floor.closed-purpose.scope.v1\0")
            .chain_update(&exact).finalize().into();
        Self { genesis, exact, signer, scope }
    }

    fn rows<'data>(&'data self, steps: &'data [(Vec<u8>, Vec<u8>)]) -> BTreeMap<&'data [u8], &'data [u8]> {
        let mut rows = BTreeMap::from([(GENESIS_KEY, self.exact.as_slice())]);
        for (key, value) in steps {
            rows.insert(key.as_slice(), value.as_slice());
        }
        rows
    }

    fn resign(&self, bytes: &mut [u8]) {
        let message = [STEP_DOMAIN, &bytes[..BODY_BYTES]].concat();
        bytes[BODY_BYTES..].copy_from_slice(&self.signer.sign(&message).to_bytes());
    }

    fn step(&self, generation: u64, phase: PhaseV1, previous: &[(Vec<u8>, Vec<u8>)]) -> (Vec<u8>, Vec<u8>) {
        let mut key = vec![b'd'];
        key.extend_from_slice(&generation.to_be_bytes());
        key.push(phase as u8);
        let mut bytes = vec![0; STEP_BYTES];
        bytes[..8].copy_from_slice(b"AOSRDS01");
        bytes[9] = 1;
        bytes[12] = phase as u8;
        bytes[16..48].copy_from_slice(&self.genesis.digest().unwrap());
        bytes[48..56].copy_from_slice(&generation.to_be_bytes());
        bytes[56..72].fill(generation as u8 + 12);
        bytes[72..88].fill(13);
        if let Some((_, previous)) = previous.last() {
            let digest = Sha256::new().chain_update(STEP_DOMAIN).chain_update(previous).finalize();
            bytes[88..120].copy_from_slice(&digest);
            if matches!(phase, PhaseV1::Measured | PhaseV1::Quarantined | PhaseV1::Quiescent) {
                bytes[256..BODY_BYTES].copy_from_slice(&previous[256..BODY_BYTES]);
            }
        }
        let sequence = INITIAL_SEQUENCE + previous.len() as u64 * 3;
        let head = canonical_purpose_main_head_v1(
            NvCustodyEndpointV1::RuntimeDeployment, self.scope, sequence, &self.rows(previous),
        ).unwrap();
        bytes[120..128].copy_from_slice(&sequence.to_be_bytes());
        bytes[128..160].copy_from_slice(&head);
        bytes[160..176].fill(previous.len() as u8 + 20);
        bytes[176..192].fill(14);
        bytes[192..224].fill(15);
        bytes[224..256].fill(16);
        if phase == PhaseV1::Started {
            bytes[256..272].fill(17);
            bytes[272..276].copy_from_slice(&100_u32.to_be_bytes());
            bytes[276..280].copy_from_slice(&101_u32.to_be_bytes());
            for offset in (280..400).step_by(8) {
                bytes[offset..offset + 8].copy_from_slice(&(offset as u64).to_be_bytes());
            }
            // Zero-cap DATA here is not the real specimen's capability claim.
            bytes[480..488].copy_from_slice(&[1, 2, 0, 1, 1, 2, 0, 1]);
        }
        if phase == PhaseV1::Measured {
            bytes[488..520].copy_from_slice(&self.genesis.supervisor_filter);
            bytes[520..552].copy_from_slice(&self.genesis.payload_filter);
        }
        self.resign(&mut bytes);
        (key, bytes)
    }

    pub(crate) fn canonical_steps(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut steps = Vec::new();
        for phase in [PhaseV1::Prepared, PhaseV1::Started, PhaseV1::Measured, PhaseV1::Quiescent] {
            steps.push(self.step(1, phase, &steps));
        }
        steps
    }

    pub(crate) fn current(&self, steps: &[(Vec<u8>, Vec<u8>)]) -> Result<(), NvCustodyErrorV1> {
        require_rows(
            INITIAL_SEQUENCE + steps.len() as u64 * 3, &self.rows(steps), &self.exact,
            &self.genesis, self.signer.verifying_key(), self.scope,
        )
    }
}

#[test]
fn unrun_genesis_native_uuid_is_nonrecursive_v8_and_binds_all_signed_bytes() {
    let fixture = Fixture::new();
    let identity = genesis_native_transaction_v1(&fixture.exact).unwrap();
    let digest = Sha256::new()
        .chain_update(b"aos.runtime-deployment.genesis-native-transaction.v1\0")
        .chain_update(&fixture.exact)
        .finalize();
    let mut expected: [u8; 16] = digest[..16].try_into().unwrap();
    expected[6] = (expected[6] & 0x0f) | 0x80;
    expected[8] = (expected[8] & 0x3f) | 0x80;

    assert_eq!(identity, expected);
    assert_eq!(identity[6] >> 4, 8);
    assert_eq!(identity[8] >> 6, 2);
    assert_ne!(&identity[8..], b"compact1");
    let mut different_signature = fixture.exact.clone();
    different_signature[SIGNED_GENESIS_BYTES - 1] ^= 1;
    assert_ne!(genesis_native_transaction_v1(&different_signature).unwrap(), identity);
    assert!(genesis_native_transaction_v1(&fixture.exact[..SIGNED_GENESIS_BYTES - 1]).is_err());
}

#[test]
fn unrun_signed_phase_uuid_cannot_collide_with_genesis_or_native_compaction() {
    let fixture = Fixture::new();
    let mut prepared = fixture.step(1, PhaseV1::Prepared, &[]);
    prepared.1[160..176].copy_from_slice(&genesis_native_transaction_v1(&fixture.exact).unwrap());
    fixture.resign(&mut prepared.1);
    assert!(fixture.current(core::slice::from_ref(&prepared)).is_err());

    prepared.1[160..168].copy_from_slice(&1_u64.to_le_bytes());
    prepared.1[168..176].copy_from_slice(b"compact1");
    fixture.resign(&mut prepared.1);
    assert!(fixture.current(&[prepared]).is_err());
}

#[test]
fn unrun_same_phase_decoder_compares_actual_uuid_and_native_begin_sequence() {
    let fixture = Fixture::new();
    let prepared = fixture.step(1, PhaseV1::Prepared, &[]);
    let native_identity = array(&prepared.1, 160).unwrap();
    let signer = fixture.signer.verifying_key();

    assert!(require_native_step_binding_v1(
        &prepared.0, &prepared.1, &fixture.genesis, signer, native_identity, 4,
    ).is_ok());
    assert!(require_native_step_binding_v1(
        &prepared.0, &prepared.1, &fixture.genesis, signer, [90; 16], 4,
    ).is_err());
    assert!(require_native_step_binding_v1(
        &prepared.0, &prepared.1, &fixture.genesis, signer, native_identity, 7,
    ).is_err());

    let mut wrong_signature = prepared.1.clone();
    wrong_signature[BODY_BYTES] ^= 1;
    assert!(require_native_step_binding_v1(
        &prepared.0, &wrong_signature, &fixture.genesis, signer, native_identity, 4,
    ).is_err());
}

#[test]
fn unrun_complete_prefixes_preserve_original_history_and_exact_transaction() {
    let fixture = Fixture::new();
    let mut steps = Vec::new();
    assert!(fixture.current(&steps).is_ok());

    for phase in [PhaseV1::Prepared, PhaseV1::Started, PhaseV1::Measured, PhaseV1::Quiescent] {
        let next = fixture.step(1, phase, &steps);
        let transaction_id = array(&next.1, 160).unwrap();
        let transaction = JournalTransaction::new(transaction_id, vec![
            JournalRecord::put(NAMESPACE, next.0.clone(), next.1.clone()),
        ]).unwrap();

        assert!(require_append(
            INITIAL_SEQUENCE + steps.len() as u64 * 3, &fixture.rows(&steps), &transaction,
            &fixture.exact, &fixture.genesis, fixture.signer.verifying_key(), fixture.scope,
        ).is_ok());
        steps.push(next);
        assert!(fixture.current(&steps).is_ok());
    }
    steps.push(fixture.step(2, PhaseV1::Prepared, &steps));
    assert!(fixture.current(&steps).is_ok());
}

#[test]
fn unrun_valid_signatures_cannot_skip_start_rewrite_or_substitute_predecessor() {
    let fixture = Fixture::new();
    let prepared = fixture.step(1, PhaseV1::Prepared, &[]);
    let started = fixture.step(1, PhaseV1::Started, core::slice::from_ref(&prepared));
    let mut wrong_head = started.clone();
    wrong_head.1[128] ^= 1;
    fixture.resign(&mut wrong_head.1);
    assert!(fixture.current(&[prepared.clone(), wrong_head]).is_err());

    let next_generation = fixture.step(2, PhaseV1::Prepared, core::slice::from_ref(&prepared));
    assert!(fixture.current(&[prepared.clone(), next_generation]).is_err());
    let transaction = JournalTransaction::new([42; 16], vec![
        JournalRecord::put(NAMESPACE, started.0.clone(), started.1.clone()),
    ]).unwrap();
    assert!(require_append(7, &fixture.rows(core::slice::from_ref(&prepared)), &transaction,
        &fixture.exact, &fixture.genesis, fixture.signer.verifying_key(), fixture.scope).is_err());

    let deletion = JournalTransaction::new([43; 16], vec![
        JournalRecord::delete(NAMESPACE, prepared.0.clone()),
    ]).unwrap();
    assert!(require_append(7, &fixture.rows(core::slice::from_ref(&prepared)), &deletion,
        &fixture.exact, &fixture.genesis, fixture.signer.verifying_key(), fixture.scope).is_err());
}

#[test]
fn unrun_fault_closure_preserves_unresolved_original_observation_until_quiescent() {
    let fixture = Fixture::new();
    let mut steps = vec![fixture.step(1, PhaseV1::Prepared, &[])];
    steps.push(fixture.step(1, PhaseV1::Quarantined, &steps));
    assert!(fixture.current(&steps).is_ok());
    let mut fabricated_empty = steps.clone();
    fabricated_empty[1].1[256] = 1;
    fixture.resign(&mut fabricated_empty[1].1);
    assert!(fixture.current(&fabricated_empty).is_err());

    steps.push(fixture.step(1, PhaseV1::Quiescent, &steps));
    assert!(fixture.current(&steps).is_ok());
    steps.push(fixture.step(2, PhaseV1::Prepared, &steps));
    assert!(fixture.current(&steps).is_ok());
}

#[test]
fn unrun_foreign_rows_wrong_filter_artifacts_and_unbounded_maps_refuse() {
    let fixture = Fixture::new();
    let mut steps = vec![fixture.step(1, PhaseV1::Prepared, &[])];
    steps.push(fixture.step(1, PhaseV1::Started, &steps));
    let mut measured = fixture.step(1, PhaseV1::Measured, &steps);
    measured.1[488] ^= 1;
    fixture.resign(&mut measured.1);
    steps.push(measured);
    assert!(fixture.current(&steps).is_err());

    let mut foreign = fixture.rows(&[]);
    foreign.insert(b"runtime-tuple-v1", b"not deployment schema");
    assert!(require_rows(7, &foreign, &fixture.exact, &fixture.genesis,
        fixture.signer.verifying_key(), fixture.scope).is_err());
    assert!(require_deployment_row_bound_v1(0).is_err());
    assert!(require_deployment_row_bound_v1(MAXIMUM_ROWS + 1).is_err());
    assert_eq!(MAIN_LIMITS.maximum_records_per_transaction, 1);
}
