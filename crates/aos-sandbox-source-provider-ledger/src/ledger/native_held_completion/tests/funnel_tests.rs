//! Whole canonical Source graph/proposal tests using cryptographic DATA only.
//!
//! These fixtures contain actual encoded companion rows and use the existing
//! Complete reducers. They contain no protected snapshot, genuine clock/FD,
//! current owner signature, dispatch bridge, journal or runtime admission.

use super::recovery_tests::{
    changed, child_query, provider_terminal, recovery_query, storage_recovery_control,
};
use super::*;
use aos_sandbox_source_provider_protocol::provider_response_artifact_digest_v1;

mod lifecycle_tests;
mod negative_tests;

#[derive(Clone)]
struct Flight {
    rows: graph::Records,
    record: SourceNativeHeldCompletionRecordV1,
}

impl Flight {
    fn requested() -> Self {
        let fixture = fixtures::Graph::applying();
        let record = initial(fixture.native.clone());
        let mut rows = fixture.rows();
        rows.remove(&native_completion::native_completion_key_v2(
            record.original.acquisition_id,
        ));
        let mut value = Self {
            rows,
            record: record.clone(),
        };
        let proposal = value.append(SourceNativeHeldStepV1::Requested, record, None);
        let binding = proposal.admission().unwrap();
        assert_eq!(binding.operation_id(), fixture.acquisition.effect_id);
        assert_eq!(
            binding.normalized_intent_digest(),
            fixture.acquisition.normalized_intent.digest()
        );
        assert_eq!(
            binding.reservation_acquisition_digest(),
            fixture.native.reservation_acquisition_digest.unwrap()
        );
        value
    }

    fn proposed_rows(&self, next: &SourceNativeHeldCompletionRecordV1) -> graph::Records {
        let mut rows = self.rows.clone();
        rows.insert(
            native_completion::native_completion_key_v2(next.original.acquisition_id),
            next.to_canonical_bytes().unwrap(),
        );
        rows
    }

    fn check(
        &self,
        step: SourceNativeHeldStepV1,
        next: &SourceNativeHeldCompletionRecordV1,
        challenge: Option<&[u8]>,
    ) -> Result<SourceNativeHeldTransactionV1, crate::LedgerFormatErrorV1> {
        let after = self.proposed_rows(next);
        propose_native_held_transition_v1(
            self.rows
                .iter()
                .map(|(key, value)| (key.as_slice(), value.as_slice())),
            after
                .iter()
                .map(|(key, value)| (key.as_slice(), value.as_slice())),
            next.original.acquisition_id,
            step,
            challenge,
        )
    }

    // Encodes a structurally canonical candidate without first accepting its
    // Source-specific joins. Negative vectors still enter the full proposal funnel.
    fn check_parts(
        &self,
        step: SourceNativeHeldStepV1,
        original: &Original,
        suffix: &NativeHeldCompletionSuffixV1,
    ) -> Result<SourceNativeHeldTransactionV1, crate::LedgerFormatErrorV1> {
        self.check_suffix_claim(step, original, &suffix.to_canonical_bytes().unwrap())
    }

    fn check_suffix_claim(
        &self,
        step: SourceNativeHeldStepV1,
        original: &Original,
        suffix: &[u8],
    ) -> Result<SourceNativeHeldTransactionV1, crate::LedgerFormatErrorV1> {
        let mut body = original_body(original, b"AOSNCR05");
        body.extend_from_slice(suffix);
        let key = native_completion::native_completion_key_v2(original.acquisition_id);
        let mut after = self.rows.clone();
        after.insert(key, independent_envelope(original, 8, &body));
        propose_native_held_transition_v1(
            self.rows
                .iter()
                .map(|(key, value)| (key.as_slice(), value.as_slice())),
            after
                .iter()
                .map(|(key, value)| (key.as_slice(), value.as_slice())),
            original.acquisition_id,
            step,
            None,
        )
    }

    fn append(
        &mut self,
        step: SourceNativeHeldStepV1,
        next: SourceNativeHeldCompletionRecordV1,
        challenge: Option<&[u8]>,
    ) -> SourceNativeHeldTransactionV1 {
        let proposal = self.check(step, &next, challenge).unwrap();
        for mutation in proposal.mutations() {
            self.rows
                .insert(mutation.key().to_vec(), mutation.after().to_vec());
        }
        self.record = next;
        proposal
    }

    fn prepared() -> Self {
        let mut value = Self::requested();
        let issued = advance(&value.record, 1);
        let challenge = challenge_bytes(&issued.original, false);
        value.append(
            SourceNativeHeldStepV1::ChallengeIssued,
            issued,
            Some(&challenge),
        );
        let original = fixtures::prepared(&value.record.original);
        let root = value.record.suffix.control(Kind::RootPrepared).unwrap();
        let reply = original.accepted_reply.as_ref().unwrap();
        let storage_w = NativeHeldOwnerWitnessV1::Storage(StorageNativeHeldWitnessV1 {
            local_socket_cookie: 1,
            primary_sequence: 1,
            workspace_sequence: 1,
            request_trust_sequence: 1,
            issuance_sequence: 1,
            request_trust_generation: 1,
            request_trust_file: d(97),
            issuance: NativeHeldByteWitnessV1::new(Family::StorageIssuance, vec![98; 48], d(99))
                .unwrap(),
        })
        .to_canonical_bytes()
        .unwrap();
        let storage = PreparedNativeHeldControlV1::new(
            Kind::StorageHeld,
            evidence::full_scope(&value.record).unwrap(),
            root.digest(),
            vec![
                section(Tag::Witness, storage_w),
                section(Tag::RootPrepared, root.to_canonical_bytes()),
                section(Tag::NativeReply, reply.to_canonical_bytes()),
            ],
            NativeHeldSignerV1::Storage(reply.acceptance().signer()),
        )
        .unwrap()
        .with_signature([0xA2; 64]);
        let mut controls = value.record.suffix.controls().to_vec();
        controls.push(storage);
        let suffix = NativeHeldCompletionSuffixV1::new(
            Owner::Provider,
            2,
            value.record.suffix.flight(),
            None,
            controls,
        )
        .unwrap();
        let prepared = SourceNativeHeldCompletionRecordV1::new(original, suffix).unwrap();
        value.append(SourceNativeHeldStepV1::StoragePrepared, prepared, None);
        value
    }

    fn complete() -> Self {
        let mut value = Self::prepared();
        let spent = advance(&value.record, 3);
        let challenge = challenge_bytes(&spent.original, true);
        value.append(
            SourceNativeHeldStepV1::ChallengeSpent,
            spent,
            Some(&challenge),
        );
        let after = fixtures::completion_rows(&value.rows, &value.record);
        let key = native_completion::native_completion_key_v2(value.record.original.acquisition_id);
        let next =
            SourceNativeHeldCompletionRecordV1::from_canonical_bytes(&key, &after[&key]).unwrap();
        let proposal = propose_native_held_transition_v1(
            value.rows.iter().map(|(k, v)| (k.as_slice(), v.as_slice())),
            after.iter().map(|(k, v)| (k.as_slice(), v.as_slice())),
            next.original.acquisition_id,
            SourceNativeHeldStepV1::CompletionCommitted,
            Some(&challenge),
        )
        .unwrap();
        assert_eq!(proposal.mutations().len(), 6);
        value.rows = after;
        value.record = next;
        value
    }

    fn artifact(&self) -> ObjectDigest {
        let keys = graph::companion_keys(&self.record).unwrap();
        let crate::ledger::model::DecodedRecordV1::Attempt(attempt) =
            format::decode_record(&keys[1], &self.rows[&keys[1]]).unwrap()
        else {
            panic!("actual Attempt")
        };
        provider_response_artifact_digest_v1(attempt.method, &attempt.completed_response)
    }

    fn witness(&self, challenge: Option<&[u8]>) -> Vec<u8> {
        let NativeHeldOwnerWitnessV1::Provider(mut witness) =
            NativeHeldOwnerWitnessV1::from_canonical_bytes(
                Owner::Provider,
                &provider_witness(&self.record),
            )
            .unwrap()
        else {
            panic!("Source witness")
        };
        let rows = graph::Companions::read(&self.rows, &self.record).unwrap();
        witness.authority = rows.authority.provider;
        witness.native_namespace = rows.catalog.resource_namespace_digest;
        witness.catalog_head = NativeHeldGenerationClaimV1 {
            generation: rows.catalog.catalog_generation,
            digest: rows.catalog.catalog_digest,
        };
        witness.catalog_floor = NativeHeldGenerationClaimV1 {
            generation: rows.catalog.catalog_floor_generation,
            digest: rows.catalog.catalog_floor_digest,
        };
        witness.head_commitment = self.record.original.publication_head;
        witness.publication =
            ObjectDigest::from_bytes(Sha256::digest(&rows.catalog.canonical_publication).into());
        for (index, family) in [
            Family::ProviderAuthority,
            Family::ProviderAttempt,
            Family::ProviderAcquisition,
            Family::ProviderHolder,
            Family::ProviderHistory,
            Family::ProviderNative,
            Family::Challenge,
        ]
        .into_iter()
        .enumerate()
        {
            let key = if index < 6 {
                rows.keys[index].clone()
            } else {
                graph::challenge_key(&self.record)
            };
            let digest = if index < 6 {
                native_held_record_byte_digest_v1(family, &key, &self.rows[&key]).unwrap()
            } else {
                challenge
                    .map(|bytes| native_held_record_byte_digest_v1(family, &key, bytes).unwrap())
                    .unwrap_or(d(0))
            };
            witness.records[index] = NativeHeldByteWitnessV1::new(family, key, digest).unwrap();
        }
        NativeHeldOwnerWitnessV1::Provider(witness)
            .to_canonical_bytes()
            .unwrap()
    }

    fn held_prepared() -> Self {
        let mut value = Self::complete();
        let storage = value.record.suffix.control(Kind::StorageHeld).unwrap();
        let challenge = challenge_bytes(&value.record.original, true);
        let prepared = PreparedNativeHeldControlV1::new(
            Kind::ProviderHeld,
            evidence::full_scope(&value.record).unwrap(),
            storage.digest(),
            vec![
                section(Tag::Witness, value.witness(Some(&challenge))),
                section(Tag::StorageHeld, storage.to_canonical_bytes()),
                section(Tag::SourceArtifact, value.artifact().as_bytes().to_vec()),
            ],
            NativeHeldSignerV1::SourceProvider(
                value
                    .record
                    .original
                    .canonical_request
                    .as_ref()
                    .unwrap()
                    .signer()
                    .clone(),
            ),
        )
        .unwrap();
        let next = changed(
            &value.record,
            5,
            Some(prepared),
            value.record.suffix.controls().to_vec(),
        );
        value.append(SourceNativeHeldStepV1::HeldPrepared, next, Some(&challenge));
        value
    }

    fn store(&mut self, step: SourceNativeHeldStepV1, phase: u8) {
        let mut controls = self.record.suffix.controls().to_vec();
        controls.push(
            self.record
                .suffix
                .prepared()
                .unwrap()
                .clone()
                .with_signature([0xAD; 64]),
        );
        let next = changed(&self.record, phase, None, controls);
        self.append(step, next, None);
    }

    fn root_disposition(&self, accepted: bool) -> RootNativeDispositionAssertionV1 {
        RootNativeDispositionAssertionV1 {
            disposition: if accepted {
                NativeHeldDispositionV1::Accepted
            } else {
                NativeHeldDispositionV1::Closed
            },
            observation: if accepted {
                RootNativeObservationV1::ProviderHeldObserved
            } else {
                RootNativeObservationV1::PreparedOnly
            },
            scope: if accepted {
                evidence::full_scope(&self.record).unwrap()
            } else {
                *self
                    .record
                    .suffix
                    .control(Kind::RootPrepared)
                    .unwrap()
                    .scope()
            },
            source_artifact: if accepted { self.artifact() } else { d(0) },
            descriptor_commitment: if accepted {
                self.record.original.descriptor_commitment
            } else {
                d(0)
            },
            records: root_witness().records,
        }
    }

    fn root_recorded(&mut self, accepted: bool) {
        let root = self.record.suffix.control(Kind::RootPrepared).unwrap();
        let assertion = self.root_disposition(accepted);
        let mut sections = vec![section(
            Tag::Witness,
            NativeHeldOwnerWitnessV1::Root(root_witness())
                .to_canonical_bytes()
                .unwrap(),
        )];
        sections.push(if accepted {
            section(Tag::SourceArtifact, self.artifact().as_bytes().to_vec())
        } else {
            section(Tag::RootPrepared, root.to_canonical_bytes())
        });
        sections.push(section(
            Tag::RootDispositionAssertion,
            assertion.to_canonical_bytes().unwrap().to_vec(),
        ));
        let control = PreparedNativeHeldControlV1::new(
            if accepted {
                Kind::RootAccepted
            } else {
                Kind::RootClosed
            },
            assertion.scope,
            if accepted {
                self.record
                    .suffix
                    .control(Kind::ProviderHeld)
                    .unwrap()
                    .digest()
            } else {
                root.digest()
            },
            sections,
            root.prepared().signer().clone(),
        )
        .unwrap()
        .with_signature([0xA4; 64]);
        let spent = self.record.original.state == Outer::Active;
        let challenge = challenge_bytes(&self.record.original, spent);
        let actual_challenge = (self.record.suffix.phase() != 0).then_some(challenge.as_slice());
        let relay = PreparedNativeHeldControlV1::new(
            Kind::ProviderRelay,
            evidence::full_scope(&self.record).unwrap(),
            control.digest(),
            vec![
                section(Tag::Witness, self.witness(actual_challenge)),
                section(Tag::RootDispositionControl, control.to_canonical_bytes()),
            ],
            NativeHeldSignerV1::SourceProvider(
                self.record
                    .original
                    .canonical_request
                    .as_ref()
                    .unwrap()
                    .signer()
                    .clone(),
            ),
        )
        .unwrap();
        let mut controls = self.record.suffix.controls().to_vec();
        controls.push(control);
        let next = changed(&self.record, 7, Some(relay), controls);
        self.append(
            SourceNativeHeldStepV1::RootDispositionPrepared,
            next,
            actual_challenge,
        );
    }

    fn first_query(&mut self, clears_held: bool) {
        let disposition = if clears_held {
            self.root_disposition(false)
        } else {
            evidence::root_disposition(&self.record)
                .unwrap()
                .unwrap_or_else(|| self.root_disposition(false))
        };
        let parent = recovery_query(&self.record, disposition);
        let mut controls = self.record.suffix.controls().to_vec();
        controls.push(parent);
        let next = changed(
            &self.record,
            7,
            if clears_held {
                None
            } else {
                self.record.suffix.prepared().cloned()
            },
            controls,
        );
        self.append(SourceNativeHeldStepV1::RootRecoveryRecorded, next, None);
    }

    fn prepare_child(&mut self) {
        let parent = self.record.suffix.control(Kind::RootRecoveryQuery).unwrap();
        let child = child_query(&self.record, parent);
        let next = changed(
            &self.record,
            7,
            Some(child),
            self.record.suffix.controls().to_vec(),
        );
        self.append(SourceNativeHeldStepV1::StorageRecoveryPrepared, next, None);
    }

    fn record_cold_storage(&mut self) {
        self.prepare_child();
        self.store(SourceNativeHeldStepV1::StorageRecoveryQueryStored, 7);
        let reply = self
            .record
            .original
            .accepted_reply
            .clone()
            .unwrap_or_else(|| {
                fixtures::prepared(&self.record.original)
                    .accepted_reply
                    .unwrap()
            });
        let storage = storage_recovery_control(&self.record, &reply);
        let mut controls = self.record.suffix.controls().to_vec();
        controls.push(storage);
        let next = changed(&self.record, 8, None, controls);
        self.append(SourceNativeHeldStepV1::StorageRecoveryRecorded, next, None);
    }

    fn settle_cold(&mut self) {
        self.record_cold_storage();
        let artifact = if self.record.original.state == Outer::Active {
            self.artifact()
        } else {
            d(0)
        };
        let terminal = provider_terminal(&self.record, artifact);
        let next = changed(
            &self.record,
            8,
            Some(terminal),
            self.record.suffix.controls().to_vec(),
        );
        self.append(SourceNativeHeldStepV1::ProviderRecoveryPrepared, next, None);
        self.store(SourceNativeHeldStepV1::ProviderRecoveryStored, 9);
    }

    fn record_normal_storage(&mut self) {
        use aos_sandbox_source_provider_protocol::native_held_completion::assertion::{
            NativeHeldSettlementV1, StorageNativeSettlementAssertionV1,
        };

        self.store(SourceNativeHeldStepV1::RelayStored, 7);
        let disposition = evidence::root_disposition(&self.record).unwrap().unwrap();
        let reply = self.record.original.accepted_reply.as_ref().unwrap();
        let assertion = StorageNativeSettlementAssertionV1 {
            disposition: disposition.disposition,
            scope: evidence::full_scope(&self.record).unwrap(),
            root_disposition: disposition.digest().unwrap(),
            acceptance: reply.acceptance().acceptance().clone(),
        };
        let settlement = NativeHeldSettlementV1 {
            disposition: disposition.disposition,
            root_disposition: assertion.root_disposition,
            storage_settlement: assertion.digest().unwrap(),
            provider_settlement: d(0),
        };
        let storage = self.record.suffix.control(Kind::StorageHeld).unwrap();
        let control = PreparedNativeHeldControlV1::new(
            Kind::StorageSettled,
            assertion.scope,
            self.record
                .suffix
                .control(Kind::ProviderRelay)
                .unwrap()
                .digest(),
            vec![
                section(
                    Tag::Witness,
                    storage.prepared().section(Tag::Witness).unwrap().to_vec(),
                ),
                section(
                    Tag::Settlement,
                    settlement.to_canonical_bytes().unwrap().to_vec(),
                ),
            ],
            storage.prepared().signer().clone(),
        )
        .unwrap()
        .with_signature([0xA6; 64]);
        let mut controls = self.record.suffix.controls().to_vec();
        controls.push(control);
        let next = changed(&self.record, 8, None, controls);
        self.append(
            SourceNativeHeldStepV1::StorageSettlementRecorded,
            next,
            None,
        );
    }

    fn settle_normal(&mut self) {
        self.record_normal_storage();
        let challenge = challenge_bytes(&self.record.original, true);
        let settlement = evidence::settlement(&self.record).unwrap().unwrap();
        let prepared = PreparedNativeHeldControlV1::new(
            Kind::ProviderSettled,
            evidence::full_scope(&self.record).unwrap(),
            self.record
                .suffix
                .control(Kind::StorageSettled)
                .unwrap()
                .digest(),
            vec![
                section(Tag::Witness, self.witness(Some(&challenge))),
                section(
                    Tag::Settlement,
                    settlement.to_canonical_bytes().unwrap().to_vec(),
                ),
            ],
            NativeHeldSignerV1::SourceProvider(
                self.record
                    .original
                    .canonical_request
                    .as_ref()
                    .unwrap()
                    .signer()
                    .clone(),
            ),
        )
        .unwrap();
        let next = changed(
            &self.record,
            8,
            Some(prepared),
            self.record.suffix.controls().to_vec(),
        );
        self.append(
            SourceNativeHeldStepV1::ProviderSettledPrepared,
            next,
            Some(&challenge),
        );
        self.store(SourceNativeHeldStepV1::ProviderSettledStored, 9);

        let terminal = PreparedNativeHeldControlV1::new(
            Kind::RootTerminalRecorded,
            evidence::full_scope(&self.record).unwrap(),
            self.record
                .suffix
                .control(Kind::ProviderSettled)
                .unwrap()
                .digest(),
            vec![
                section(
                    Tag::Witness,
                    NativeHeldOwnerWitnessV1::Root(root_witness())
                        .to_canonical_bytes()
                        .unwrap(),
                ),
                section(
                    Tag::Settlement,
                    settlement.to_canonical_bytes().unwrap().to_vec(),
                ),
            ],
            self.record
                .suffix
                .control(Kind::RootPrepared)
                .unwrap()
                .prepared()
                .signer()
                .clone(),
        )
        .unwrap()
        .with_signature([0xAD; 64]);
        let mut controls = self.record.suffix.controls().to_vec();
        controls.push(terminal);
        let next = changed(&self.record, 10, None, controls);
        self.append(SourceNativeHeldStepV1::RootTerminalRecorded, next, None);
    }
}

#[test]
fn full_graph_normal_complete_and_terminal_keep_all_six_authoritative_rows() {
    for accepted in [false, true] {
        let mut flight = Flight::held_prepared();
        flight.store(SourceNativeHeldStepV1::HeldStored, 6);
        let completed = flight.rows.clone();
        flight.root_recorded(accepted);
        flight.settle_normal();
        assert_eq!(flight.record.suffix.phase(), 10);
        assert_eq!(flight.record.original.state, Outer::Active);
        let native_key =
            native_completion::native_completion_key_v2(flight.record.original.acquisition_id);
        for (key, value) in completed {
            if key != native_key {
                assert_eq!(flight.rows[&key], value);
            }
        }
        assert!(
            flight
                .record
                .suffix
                .control(Kind::RootTerminalRecorded)
                .is_some()
        );
        assert_eq!(
            evidence::artifact(&flight.record).unwrap(),
            flight.artifact()
        );
    }
}

#[test]
fn full_graph_replaces_unescaped5_only_after_same_first_root9_and_preserves_original() {
    for accepted in [false, true] {
        let mut flight = Flight::held_prepared();
        flight.store(SourceNativeHeldStepV1::HeldStored, 6);
        flight.root_recorded(accepted);
        let original = flight.record.original.clone();
        let prior_archives = flight.record.suffix.controls().to_vec();
        let without_query = child_query(
            &flight.record,
            &recovery_query(&flight.record, flight.root_disposition(accepted)),
        );
        let mut rejected_original = flight.record.original.clone();
        rejected_original.revision += 1;
        let rejected_suffix = NativeHeldCompletionSuffixV1::new(
            Owner::Provider,
            7,
            flight.record.suffix.flight(),
            Some(without_query),
            prior_archives.clone(),
        )
        .unwrap();
        assert!(
            flight
                .check_parts(
                    SourceNativeHeldStepV1::StorageRecoveryPrepared,
                    &rejected_original,
                    &rejected_suffix
                )
                .is_err()
        );
        flight.first_query(false);
        flight.prepare_child();
        let mut expected = original;
        expected.revision = flight.record.original.revision;
        assert_eq!(flight.record.original, expected);
        assert!(flight.record.suffix.controls().starts_with(&prior_archives));
        assert!(flight.record.suffix.control(Kind::ProviderRelay).is_none());
        assert_eq!(
            flight.record.suffix.prepared().unwrap().kind(),
            Kind::ProviderStorageRecoveryQuery
        );
    }
}

#[test]
fn full_graph_closed_query_clears_only_unescaped3_and_preserves_completed_artifact() {
    let mut flight = Flight::held_prepared();
    let complete_rows = flight.rows.clone();
    let artifact = flight.artifact();
    flight.first_query(true);
    assert_eq!(flight.record.suffix.phase(), 7);
    assert_eq!(flight.record.original.state, Outer::Active);
    assert!(flight.record.suffix.prepared().is_none());
    assert!(flight.record.suffix.control(Kind::ProviderHeld).is_none());
    let native_key =
        native_completion::native_completion_key_v2(flight.record.original.acquisition_id);
    for (key, value) in complete_rows {
        if key != native_key {
            assert_eq!(flight.rows[&key], value);
        }
    }
    flight.settle_cold();
    assert_eq!(evidence::artifact(&flight.record).unwrap(), artifact);
    assert_ne!(artifact, d(0));
    assert_eq!(
        evidence::root_disposition(&flight.record)
            .unwrap()
            .unwrap()
            .source_artifact,
        d(0)
    );
}

#[test]
fn full_graph_requested_cold12_metadata_does_not_create_positive_reply_or_complete() {
    let mut flight = Flight::requested();
    flight.first_query(false);
    flight.settle_cold();
    assert_eq!(flight.record.original.state, Outer::Requested);
    assert!(flight.record.original.accepted_reply.is_none());
    assert_eq!(flight.record.original.acceptance_payload_digest, d(0));
    assert_ne!(evidence::acceptance(&flight.record).unwrap(), d(0));
    assert_eq!(evidence::artifact(&flight.record).unwrap(), d(0));
    let keys = graph::companion_keys(&flight.record).unwrap();
    let crate::ledger::model::DecodedRecordV1::Attempt(attempt) =
        format::decode_record(&keys[1], &flight.rows[&keys[1]]).unwrap()
    else {
        panic!("Attempt")
    };
    assert!(attempt.completed_response.is_empty());
    assert_eq!(
        attempt.state,
        crate::ledger::model::ProviderAttemptStateV1::Reserved
    );
}

#[test]
fn full_graph_prepared_cold12_metadata_preserves_unspent_original_reply_phase() {
    let mut flight = Flight::prepared();
    let mut original = flight.record.original.clone();
    flight.first_query(false);
    flight.settle_cold();
    original.revision = flight.record.original.revision;
    assert_eq!(flight.record.original, original);
    assert_eq!(flight.record.original.state, Outer::Prepared);
    assert_eq!(evidence::artifact(&flight.record).unwrap(), d(0));
}
