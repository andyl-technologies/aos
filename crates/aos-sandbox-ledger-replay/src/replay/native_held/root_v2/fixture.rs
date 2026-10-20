//! Actual signed phase0, PreparedStored and discard-Root1 Closed source vectors.
//!
//! The shared Protocol fixture supplies genuine canonical original rows. Budgets
//! in transfer tests are explicit DATA inputs, not attained maxima or admission
//! proof. Authenticated Inventory/settlement and terminal ACK fixture coverage
//! remains with Protocol; this compact seam does not duplicate its owner engine.

use super::JournalError;

use aos_sandbox_protocol::domain_ledger::capacity_family::native_held::{
    NativeHeldCapacityPurposeV3, NativeHeldCapacityRecordV3, NativeHeldCapacityRequestV3,
};

use std::collections::BTreeMap;

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_protocol as protocol;
use aos_sandbox_source_provider_protocol::{
    NativeAcquireCatalogBindingV3, SourceProviderKeyUsageV1,
    native_held_completion::{
        NativeHeldControlKindV1 as ControlKind, NativeHeldOwnerV1, NativeHeldScopeV1,
        NativeHeldSectionTagV1,
        assertion::{
            NativeHeldDispositionV1, RootNativeDispositionAssertionV1, RootNativeObservationV1,
        },
        frame::{
            NativeHeldSectionV1, NativeHeldSignerV1, PreparedNativeHeldControlV1,
            SignedNativeHeldControlV1,
        },
        native_held_flight_digest_v1,
        suffix::NativeHeldCompletionSuffixV1,
        witness::{
            NativeHeldByteWitnessV1, NativeHeldGenerationClaimV1, NativeHeldOwnerWitnessV1,
            ROOT_NATIVE_WITNESS_FAMILIES_V1, RootNativeHeldWitnessV1,
            native_held_record_byte_digest_v1,
        },
    },
};
use ed25519_dalek::{Signer as _, SigningKey};
use protocol::mount_source_acquisition_state::{
    StoredRecordV2, acquisition_key, encode_mount_source_state_record_v2,
    native_held_completion::{
        RootNativeCutKindV1, RootNativeCutV1, RootNativeHeldSidecarV2,
        RootNativeNoInterestTerminalV1, native_root_sidecar_key_v2, validate_native_root_graph_v2,
    },
    provider_attempt_key, provider_head_key, provider_session_key,
    validate_mount_source_state_graph_v2,
};

#[path = "../../../../../aos-sandbox-protocol/src/mount_source_acquisition_state/native_held_completion/tests/fixture.rs"]
mod fixture;

use super::*;

fn digest(byte: u8) -> ObjectDigest {
    ObjectDigest::from_bytes([byte; 32])
}

/// Carries the existing signed test rows without any live owner or grant.
pub struct Original {
    /// Stores the canonical namespace-40 fixture records.
    pub rows: BTreeMap<Vec<u8>, Vec<u8>>,
    /// Names the exact fixed fixture attempt.
    pub attempt: [u8; 32],
    /// Carries the signed historical owner scope as DATA only.
    pub scope: NativeHeldScopeV1,
    /// Carries the existing signed witness as DATA only.
    pub witness: RootNativeHeldWitnessV1,
    /// Carries the fixed canonical Root cut as DATA only.
    pub cut: RootNativeCutV1,
}

impl Original {
    /// Builds the existing fixed signed historical test vector.
    ///
    /// # Panics
    /// Panics if the fixture's fixed canonical encodings or signatures fail.
    pub fn new() -> Self {
        let session = fixture::signed_session([19; 16], 31);
        let catalog = NativeAcquireCatalogBindingV3::new(
            digest(10),
            1,
            digest(62),
            1,
            digest(62),
            digest(63),
            digest(64),
        )
        .unwrap();
        let records = fixture::initial_signed_graph_with_catalog(
            session.clone(),
            500,
            [62; 32],
            [63; 32],
            Some(catalog),
        );
        let StoredRecordV2::ProviderQueryAttempt { value: attempt } = &records[1] else {
            panic!("original Attempt fixture")
        };
        let rows: BTreeMap<_, _> = records
            .iter()
            .map(|row| encode_mount_source_state_record_v2(row).unwrap())
            .collect();
        let keys = [
            provider_session_key(session.session_id),
            provider_attempt_key(attempt.attempt_id),
            acquisition_key(attempt.owner.owner_id()),
            provider_head_key(
                session.scope.holder_authority_id,
                session.scope.provider_authority_id,
            ),
        ];
        let witnesses = keys
            .into_iter()
            .zip(ROOT_NATIVE_WITNESS_FAMILIES_V1)
            .map(|(key, family)| {
                let commitment =
                    native_held_record_byte_digest_v1(family, &key, &rows[&key]).unwrap();
                NativeHeldByteWitnessV1::new(family, key, commitment).unwrap()
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let root_request = ObjectDigest::from_bytes(attempt.signed_request_digest);
        let mount_attempt = ObjectDigest::from_bytes(attempt.attempt_id);
        let source_session = ObjectDigest::from_bytes(session.session_binding);
        let scope = NativeHeldScopeV1 {
            flight: native_held_flight_digest_v1(root_request, mount_attempt, source_session),
            original_source_session: source_session,
            mount_attempt,
            provider_attempt: digest(0),
            provider_acquisition: ObjectDigest::from_bytes(
                attempt.provider_acquisition.unwrap().acquisition_id,
            ),
            original_root_request: root_request,
            original_native_request: digest(0),
        };
        let claim = |byte| NativeHeldGenerationClaimV1 {
            generation: 1,
            digest: digest(byte),
        };
        let witness = RootNativeHeldWitnessV1 {
            local_socket_cookie: 7,
            journal_sequence: 1,
            planning_sequence: 1,
            trust: claim(16),
            revocation: claim(17),
            provider_head: claim(62),
            provider_floor: claim(62),
            publication: digest(64),
            records: witnesses,
        };
        let legacy = validate_mount_source_state_graph_v2(
            rows.iter().map(|(k, v)| (k.as_slice(), v.as_slice())),
        )
        .unwrap();
        let cut = RootNativeCutV1::capture(
            RootNativeCutKindV1::Admission,
            [100; 16],
            &legacy,
            attempt.attempt_id,
        )
        .unwrap();
        Self {
            rows,
            attempt: attempt.attempt_id,
            scope,
            witness,
            cut,
        }
    }

    /// Builds the existing Prepared control over this historical vector.
    ///
    /// # Panics
    /// Panics if the supplied fixture fields no longer form the fixed vector.
    pub fn prepared(&self) -> PreparedNativeHeldControlV1 {
        PreparedNativeHeldControlV1::new(
            ControlKind::RootPrepared,
            self.scope,
            digest(0),
            vec![
                NativeHeldSectionV1::new(
                    NativeHeldSectionTagV1::Witness,
                    NativeHeldOwnerWitnessV1::Root(self.witness.clone())
                        .to_canonical_bytes()
                        .unwrap(),
                )
                .unwrap(),
            ],
            NativeHeldSignerV1::SourceProvider(fixture::signer(
                [1; 16],
                [22; 16],
                SourceProviderKeyUsageV1::RootMountRecord,
                &SigningKey::from_bytes(&[12; 32]),
            )),
        )
        .unwrap()
    }

    fn sidecar(&self, stored: bool, closed: bool) -> RootNativeHeldSidecarV2 {
        let prepared = self.prepared();
        let controls = if stored {
            let signature = SigningKey::from_bytes(&[12; 32])
                .sign(&prepared.signature_message())
                .to_bytes();
            vec![prepared.clone().with_signature(signature)]
        } else {
            Vec::<SignedNativeHeldControlV1>::new()
        };
        let phase = if closed {
            10
        } else if stored {
            1
        } else {
            0
        };
        let r = closed.then(|| RootNativeDispositionAssertionV1 {
            disposition: NativeHeldDispositionV1::Closed,
            observation: RootNativeObservationV1::PreparedOnly,
            scope: self.scope,
            source_artifact: digest(0),
            descriptor_commitment: digest(0),
            records: self.witness.records.clone(),
        });
        let legacy = validate_mount_source_state_graph_v2(
            self.rows.iter().map(|(k, v)| (k.as_slice(), v.as_slice())),
        )
        .unwrap();
        let disposition = closed.then(|| {
            RootNativeCutV1::capture(
                RootNativeCutKindV1::Disposition,
                [101; 16],
                &legacy,
                self.attempt,
            )
            .unwrap()
        });
        RootNativeHeldSidecarV2::new(
            self.scope,
            [0; 16],
            r,
            None,
            None,
            NativeHeldCompletionSuffixV1::new(
                NativeHeldOwnerV1::Root,
                phase,
                self.scope.flight,
                if stored || closed {
                    None
                } else {
                    Some(prepared)
                },
                controls,
            )
            .unwrap(),
            self.cut.clone(),
            disposition,
            None,
        )
        .unwrap()
    }

    /// Decodes the existing stored or closed historical graph variant.
    ///
    /// # Panics
    /// Panics for a malformed fixture or an inconsistent variant combination.
    pub fn graph(&self, stored: bool, closed: bool) -> RootNativeHeldGraphV2 {
        let mut rows = self.rows.clone();
        rows.insert(
            native_root_sidecar_key_v2(self.attempt).unwrap(),
            self.sidecar(stored, closed).to_canonical_bytes().unwrap(),
        );
        validate_native_root_graph_v2(rows.iter().map(|(k, v)| (k.as_slice(), v.as_slice())))
            .unwrap()
    }

    /// Builds the former explicitly sized historical capacity test record.
    ///
    /// # Panics
    /// Panics if the graph or count violates the canonical fixture bounds.
    pub fn floor(&self, graph: &RootNativeHeldGraphV2, count: u32) -> NativeHeldCapacityRecordV3 {
        let binding = original_binding(graph, graph, self.attempt).unwrap();
        let sidecar = &graph.sidecars()[&self.attempt];
        let cut = sidecar.admission_cut();
        let prepared = sidecar.suffix().prepared().unwrap();
        let admission = cut.capture_transaction();
        let request = NativeHeldCapacityRequestV3 {
            purpose: NativeHeldCapacityPurposeV3::Root,
            owner_id: binding.mount_attempt(),
            owner_digest: cut.original_attempt(self.attempt).record_digest,
            operation_id: cut.acquisition().acquire.operation_id,
            artifact_digest: graph.legacy().provider_attempts[&self.attempt].signed_request_digest,
            checkpoint_digest: *prepared.digest().as_bytes(),
            chain_head_digest: cut.head().record_digest,
            future_transactions: count,
            terminal_records: 100,
            terminal_bytes: 10_000_000,
            poison_records: 100,
            poison_bytes: 10_000_000,
        };
        binding.require_request(request, admission).unwrap();

        NativeHeldCapacityRecordV3::new(request, admission)
        .map_err(JournalError::from)
        .unwrap()
    }
}
