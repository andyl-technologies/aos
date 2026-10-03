//! Canonical-format tests using only nonauthorizing synthetic data.
//!
//! Golden preimages below are assembled independently from reviewed wire orders,
//! fixed widths and literal domains. Regeneration requires reviewing these orders
//! against the cumulative R3+R4 contract, never accepting encoder output blindly.
//! The existing native fixture supplies typed request/reply bytes; no descriptor,
//! protected owner, measurement, currentness or production signing factory exists.

use aos_sandbox_core::ObjectDigest;
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest as _, Sha256};

use crate::{
    SignedStorageNativeAcquireRequestV2, SourceProviderAuthorityV1, SourceProviderMethod,
    StorageNativeAcquireReplyV3, digest_signed_request,
};

use super::assertion::*;
use super::frame::*;
use super::recovery::*;
use super::suffix::NativeHeldCompletionSuffixV1;
use super::witness::*;
use super::*;

type Kind = NativeHeldControlKindV1;
type Owner = NativeHeldOwnerV1;
type Tag = NativeHeldSectionTagV1;

fn d(byte: u8) -> ObjectDigest {
    ObjectDigest::from_bytes([byte; 32])
}

fn zero() -> ObjectDigest {
    d(0)
}

fn witness(family: NativeHeldRecordFamilyV1, byte: u8) -> NativeHeldByteWitnessV1 {
    let prefix: &[u8] = match family {
        NativeHeldRecordFamilyV1::RootSession => b"aos.mount.source-provider-session.v2\0",
        NativeHeldRecordFamilyV1::RootAttempt => b"aos.mount.source-provider-query-attempt.v2\0",
        NativeHeldRecordFamilyV1::RootAcquisition => b"aos.mount.source-acquisition.v2\0",
        NativeHeldRecordFamilyV1::RootHead => b"aos.mount.source-provider-head.v2\0",
        NativeHeldRecordFamilyV1::ProviderAuthority => b"aos.source-provider.authority.v1\0",
        NativeHeldRecordFamilyV1::ProviderAttempt => b"aos.source-provider.attempt.v1\0",
        NativeHeldRecordFamilyV1::ProviderAcquisition => b"aos.source-provider.acquisition.v1\0",
        NativeHeldRecordFamilyV1::ProviderHolder => b"aos.source-provider.session.v1\0",
        NativeHeldRecordFamilyV1::ProviderHistory => b"aos.source-provider.session-history.v1\0",
        NativeHeldRecordFamilyV1::ProviderNative => b"AOSNCK02",
        NativeHeldRecordFamilyV1::Challenge => b"AOSZHK01",
        NativeHeldRecordFamilyV1::StorageIssuance => b"",
    };
    let mut key = prefix.to_vec();
    key.resize(family.key_bytes(), byte);
    if family == NativeHeldRecordFamilyV1::ProviderAttempt {
        key[prefix.len() + 48] = SourceProviderMethod::Acquire as u8;
    }
    NativeHeldByteWitnessV1::new(family, key, d(byte)).unwrap()
}

fn generation(byte: u8) -> NativeHeldGenerationClaimV1 {
    NativeHeldGenerationClaimV1 {
        generation: u64::from(byte),
        digest: d(byte),
    }
}

struct Fixture {
    request: SignedStorageNativeAcquireRequestV2,
    reply: StorageNativeAcquireReplyV3,
    root_scope: NativeHeldScopeV1,
    full_scope: NativeHeldScopeV1,
    root_witness: RootNativeHeldWitnessV1,
    provider_witness: ProviderNativeHeldWitnessV1,
    storage_witness: StorageNativeHeldWitnessV1,
}

impl Fixture {
    fn new() -> Self {
        let (request, reply) = crate::storage_native_acquire::held_completion_fixture();
        let claims = request.request().claims();
        let root_request = digest_signed_request(request.request().signed_root_request());
        let root_scope = NativeHeldScopeV1 {
            flight: native_held_flight_digest_v1(root_request, d(80), claims.holder_session().1),
            original_source_session: claims.holder_session().1,
            mount_attempt: d(80),
            provider_attempt: zero(),
            provider_acquisition: claims.provider_acquisition().1,
            original_root_request: root_request,
            original_native_request: zero(),
        };
        let full_scope = NativeHeldScopeV1 {
            provider_attempt: d(81),
            original_native_request: request.digest(),
            ..root_scope
        };
        let root_witness = RootNativeHeldWitnessV1 {
            local_socket_cookie: 2,
            journal_sequence: 3,
            planning_sequence: 1,
            trust: generation(4),
            revocation: generation(5),
            provider_head: generation(6),
            provider_floor: generation(7),
            publication: d(8),
            records: ROOT_NATIVE_WITNESS_FAMILIES_V1.map(|family| witness(family, 9)),
        };
        let provider_witness = ProviderNativeHeldWitnessV1 {
            root_local_cookie: 10,
            storage_local_cookie: 11,
            completion_sequence: 12,
            challenge_sequence: 13,
            authority: SourceProviderAuthorityV1::new([14; 16], 15, d(16)).unwrap(),
            native_namespace: d(17),
            catalog_head: generation(18),
            catalog_floor: generation(19),
            head_commitment: d(20),
            publication: d(21),
            selected_manifest: d(22),
            backend_manifest: d(23),
            verifier_manifest: d(24),
            records: PROVIDER_NATIVE_WITNESS_FAMILIES_V1.map(|family| witness(family, 25)),
        };
        let storage_witness = StorageNativeHeldWitnessV1 {
            local_socket_cookie: 26,
            primary_sequence: 27,
            workspace_sequence: 28,
            request_trust_sequence: 29,
            issuance_sequence: 30,
            request_trust_generation: 31,
            request_trust_file: d(32),
            issuance: witness(NativeHeldRecordFamilyV1::StorageIssuance, 33),
        };
        Self {
            request,
            reply,
            root_scope,
            full_scope,
            root_witness,
            provider_witness,
            storage_witness,
        }
    }

    fn signer(&self, owner: Owner) -> NativeHeldSignerV1 {
        match owner {
            Owner::Root => NativeHeldSignerV1::SourceProvider(
                self.request
                    .request()
                    .signed_root_request()
                    .signer()
                    .clone(),
            ),
            Owner::Provider => NativeHeldSignerV1::SourceProvider(self.request.signer().clone()),
            Owner::Storage => NativeHeldSignerV1::Storage(self.reply.acceptance().signer()),
        }
    }

    fn w(&self, owner: Owner) -> NativeHeldSectionV1 {
        let value = match owner {
            Owner::Root => NativeHeldOwnerWitnessV1::Root(self.root_witness.clone()),
            Owner::Provider => NativeHeldOwnerWitnessV1::Provider(self.provider_witness.clone()),
            Owner::Storage => NativeHeldOwnerWitnessV1::Storage(self.storage_witness.clone()),
        };
        section(Tag::Witness, value.to_canonical_bytes().unwrap())
    }

    fn control(
        &self,
        kind: Kind,
        scope: NativeHeldScopeV1,
        predecessor: ObjectDigest,
        sections: Vec<NativeHeldSectionV1>,
    ) -> SignedNativeHeldControlV1 {
        PreparedNativeHeldControlV1::new(
            kind,
            scope,
            predecessor,
            sections,
            self.signer(kind.sender()),
        )
        .unwrap()
        .with_signature([0xA1; 64])
    }

    fn root_prepared(&self) -> SignedNativeHeldControlV1 {
        self.control(
            Kind::RootPrepared,
            self.root_scope,
            zero(),
            vec![self.w(Owner::Root)],
        )
    }

    fn r(
        &self,
        disposition: NativeHeldDispositionV1,
        partial: bool,
    ) -> RootNativeDispositionAssertionV1 {
        RootNativeDispositionAssertionV1 {
            disposition,
            observation: if partial {
                RootNativeObservationV1::PreparedOnly
            } else {
                RootNativeObservationV1::ProviderHeldObserved
            },
            scope: if partial {
                self.root_scope
            } else {
                self.full_scope
            },
            source_artifact: if partial { zero() } else { d(90) },
            descriptor_commitment: if disposition == NativeHeldDispositionV1::Accepted {
                self.reply.acceptance().acceptance().descriptor_commitment()
            } else {
                zero()
            },
            records: self.root_witness.records.clone(),
        }
    }

    fn storage_assertion(
        &self,
        r: &RootNativeDispositionAssertionV1,
    ) -> StorageNativeSettlementAssertionV1 {
        StorageNativeSettlementAssertionV1 {
            disposition: r.disposition,
            scope: self.full_scope,
            root_disposition: r.digest().unwrap(),
            acceptance: self.reply.acceptance().acceptance().clone(),
        }
    }

    fn provider_assertion(
        &self,
        r: &RootNativeDispositionAssertionV1,
    ) -> ProviderNativeSettlementAssertionV1 {
        ProviderNativeSettlementAssertionV1 {
            disposition: r.disposition,
            scope: self.full_scope,
            root_disposition: r.digest().unwrap(),
            storage_settlement: self.storage_assertion(r).digest().unwrap(),
            source_artifact: d(90),
        }
    }

    fn s(&self, r: &RootNativeDispositionAssertionV1, provider: bool) -> NativeHeldSettlementV1 {
        NativeHeldSettlementV1 {
            disposition: r.disposition,
            root_disposition: r.digest().unwrap(),
            storage_settlement: self.storage_assertion(r).digest().unwrap(),
            provider_settlement: if provider {
                self.provider_assertion(r).digest().unwrap()
            } else {
                zero()
            },
        }
    }

    fn hot(&self) -> Vec<SignedNativeHeldControlV1> {
        let one = self.root_prepared();
        let two = self.control(
            Kind::StorageHeld,
            self.full_scope,
            one.digest(),
            vec![
                self.w(Owner::Storage),
                section(Tag::RootPrepared, one.to_canonical_bytes()),
                section(Tag::NativeReply, self.reply.to_canonical_bytes()),
            ],
        );
        let three = self.control(
            Kind::ProviderHeld,
            self.full_scope,
            two.digest(),
            vec![
                self.w(Owner::Provider),
                section(Tag::StorageHeld, two.to_canonical_bytes()),
                section(Tag::SourceArtifact, d(90).as_bytes().to_vec()),
            ],
        );
        let r = self.r(NativeHeldDispositionV1::Accepted, false);
        let four = self.control(
            Kind::RootAccepted,
            self.full_scope,
            three.digest(),
            vec![
                self.w(Owner::Root),
                section(Tag::SourceArtifact, d(90).as_bytes().to_vec()),
                section(
                    Tag::RootDispositionAssertion,
                    r.to_canonical_bytes().unwrap().to_vec(),
                ),
            ],
        );
        let five = self.control(
            Kind::ProviderRelay,
            self.full_scope,
            four.digest(),
            vec![
                self.w(Owner::Provider),
                section(Tag::RootDispositionControl, four.to_canonical_bytes()),
            ],
        );
        let six = self.control(
            Kind::StorageSettled,
            self.full_scope,
            five.digest(),
            vec![
                self.w(Owner::Storage),
                section(
                    Tag::Settlement,
                    self.s(&r, false).to_canonical_bytes().unwrap().to_vec(),
                ),
            ],
        );
        let seven = self.control(
            Kind::ProviderSettled,
            self.full_scope,
            six.digest(),
            vec![
                self.w(Owner::Provider),
                section(
                    Tag::Settlement,
                    self.s(&r, true).to_canonical_bytes().unwrap().to_vec(),
                ),
            ],
        );
        let thirteen = self.control(
            Kind::RootTerminalRecorded,
            self.full_scope,
            seven.digest(),
            vec![
                self.w(Owner::Root),
                section(
                    Tag::Settlement,
                    self.s(&r, true).to_canonical_bytes().unwrap().to_vec(),
                ),
            ],
        );
        vec![one, two, three, four, five, six, seven, thirteen]
    }

    fn query(
        &self,
        original: ObjectDigest,
        mode: NativeHeldRecoveryModeV1,
    ) -> NativeHeldRecoveryQueryV1 {
        NativeHeldRecoveryQueryV1 {
            recovery_session: d(100),
            nonce: [101; 32],
            sequence: 102,
            mode,
            target: NativeHeldRecoveryTargetV1::RootScope,
            original_prepared: original,
            parent_root_query: zero(),
        }
    }

    fn recovery(&self) -> [SignedNativeHeldControlV1; 4] {
        let hot = self.hot();
        let r = self.r(NativeHeldDispositionV1::Accepted, false);
        let query = self.query(
            hot[0].digest(),
            NativeHeldRecoveryModeV1::SettleRecordedDisposition,
        );
        let k = RootNativeRecoveryAssertionV1 {
            phase: 6,
            runtime_status: NativeHeldRuntimeStatusV1::RecoveryOnly,
            cold_custody: NativeHeldColdCustodyV1::Unavailable,
            diagnostic_sequence: 110,
            records: self.root_witness.records.clone(),
            disposition: Some(r.clone()),
            hot_archive: Some(hot[3].to_canonical_bytes()),
            settlement: Some(self.s(&r, true)),
        };
        let nine = self.control(
            Kind::RootRecoveryQuery,
            self.root_scope,
            zero(),
            vec![
                section(
                    Tag::RecoveryQuery,
                    query.to_canonical_bytes().unwrap().to_vec(),
                ),
                section(Tag::RootRecoveryAssertion, k.to_canonical_bytes().unwrap()),
            ],
        );
        let child_query = NativeHeldRecoveryQueryV1 {
            nonce: [111; 32],
            sequence: 112,
            target: NativeHeldRecoveryTargetV1::NativeScope,
            parent_root_query: nine.digest(),
            ..query
        };
        let eleven = self.control(
            Kind::ProviderStorageRecoveryQuery,
            self.full_scope,
            nine.digest(),
            vec![
                section(
                    Tag::RecoveryQuery,
                    child_query.to_canonical_bytes().unwrap().to_vec(),
                ),
                section(Tag::RootRecoveryControl, nine.to_canonical_bytes()),
            ],
        );
        let z = StorageNativeRecoveryStateV1 {
            fields: NativeHeldRecoveryFieldsV1 {
                phase: 4,
                runtime_status: NativeHeldRuntimeStatusV1::RecoveryOnly,
                row_class: NativeHeldRecoveryRowClassV1::Native,
                child_status: NativeHeldRecoveryChildStatusV1::NotQueried,
                diagnostic_sequence: 120,
                native_request: self.request.digest(),
                acceptance: self.reply.acceptance().acceptance().digest(),
                root_disposition: r.digest().unwrap(),
                storage_settlement: self.storage_assertion(&r).digest().unwrap(),
                provider_settlement: zero(),
                witness: Some(self.storage_witness.issuance.clone()),
                disposition: Some(r.clone()),
                own_assertion: self
                    .storage_assertion(&r)
                    .to_canonical_bytes()
                    .unwrap()
                    .to_vec(),
                hot_terminal: Some(hot[5].to_canonical_bytes()),
                child: None,
            },
        };
        let twelve = self.control(
            Kind::StorageRecoveryState,
            self.full_scope,
            eleven.digest(),
            vec![
                section(
                    Tag::RecoveryQuery,
                    child_query.to_canonical_bytes().unwrap().to_vec(),
                ),
                section(Tag::StorageRecoveryState, z.to_canonical_bytes().unwrap()),
            ],
        );
        let v = ProviderNativeRecoveryStateV1 {
            fields: NativeHeldRecoveryFieldsV1 {
                phase: 9,
                runtime_status: NativeHeldRuntimeStatusV1::RecoveryOnly,
                row_class: NativeHeldRecoveryRowClassV1::Native,
                child_status: NativeHeldRecoveryChildStatusV1::VerifiedState,
                diagnostic_sequence: 130,
                native_request: self.request.digest(),
                acceptance: self.reply.acceptance().acceptance().digest(),
                root_disposition: r.digest().unwrap(),
                storage_settlement: self.storage_assertion(&r).digest().unwrap(),
                provider_settlement: self.provider_assertion(&r).digest().unwrap(),
                witness: Some(self.provider_witness.records[5].clone()),
                disposition: Some(r),
                own_assertion: self
                    .provider_assertion(&self.r(NativeHeldDispositionV1::Accepted, false))
                    .to_canonical_bytes()
                    .unwrap()
                    .to_vec(),
                hot_terminal: Some(hot[6].to_canonical_bytes()),
                child: Some(twelve.to_canonical_bytes()),
            },
        };
        let ten = self.control(
            Kind::ProviderRecoveryState,
            self.full_scope,
            nine.digest(),
            vec![
                section(
                    Tag::RecoveryQuery,
                    query.to_canonical_bytes().unwrap().to_vec(),
                ),
                section(Tag::ProviderRecoveryState, v.to_canonical_bytes().unwrap()),
            ],
        );
        [nine, ten, eleven, twelve]
    }
}

fn section(tag: Tag, bytes: Vec<u8>) -> NativeHeldSectionV1 {
    NativeHeldSectionV1::new(tag, bytes).unwrap()
}

#[test]
fn canonical_hot_controls_pin_exact_reviewed_widths_and_roundtrip() {
    let fixture = Fixture::new();
    let hot = fixture.hot();

    for (control, width) in hot
        .iter()
        .zip([1130, 2966, 4612, 1900, 3506, 740, 1710, 1242])
    {
        let bytes = control.to_canonical_bytes();
        assert_eq!(bytes.len(), width, "{:?}", control.kind());
        assert_eq!(
            SignedNativeHeldControlV1::from_canonical_bytes(&bytes).unwrap(),
            *control
        );
    }
    assert_eq!(fixture.reply.to_canonical_bytes().len(), 1192);
    assert_eq!(
        fixture
            .storage_assertion(&fixture.r(NativeHeldDispositionV1::Accepted, false))
            .to_canonical_bytes()
            .unwrap()
            .len(),
        488
    );
    assert_eq!(
        fixture
            .provider_assertion(&fixture.r(NativeHeldDispositionV1::Accepted, false))
            .to_canonical_bytes()
            .unwrap()
            .len(),
        336
    );
}

#[test]
fn root_prepared_golden_header_scope_signer_and_domains_are_independent() {
    let fixture = Fixture::new();
    let control = fixture.root_prepared();
    let bytes = control.to_canonical_bytes();
    let mut expected_header = b"AOSNHC01".to_vec();
    expected_header.extend_from_slice(&[0, 1, 1, 1, 0, 0, 3, 154, 0, 0, 0, 0, 0, 0, 0, 0]);

    assert_eq!(&bytes[..24], expected_header);
    assert_eq!(&bytes[24..248], fixture.root_scope.to_canonical_bytes());
    assert_eq!(&bytes[248..280], &[0; 32]);
    assert_eq!(&bytes[280..288], &1_u64.to_be_bytes());
    assert_eq!(&bytes[288..296], &[0, 1, 0, 0, 0, 0, 0, 0]);
    assert_eq!(&bytes[296..304], &[0, 1, 0, 0, 0, 0, 2, 130]);
    assert_eq!(bytes.len() - 64 - (304 + 642), 120);
    let mut message = b"aos.sandbox.native-held-completion.signature.v1\0".to_vec();
    message.push(2);
    message.extend_from_slice(&bytes[..bytes.len() - 64]);
    assert_eq!(control.prepared().signature_message(), message);
    let expected = ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.native-held-completion.frame.v1\0")
            .chain_update(&bytes)
            .finalize()
            .into(),
    );
    assert_eq!(control.digest(), expected);
    let prepared = ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.native-held-completion.prepared-frame.v1\0")
            .chain_update(&bytes[..bytes.len() - 64])
            .finalize()
            .into(),
    );
    assert_eq!(control.prepared().digest(), prepared);
    assert_ne!(prepared, expected);
}

#[test]
fn native_full_join_preserves_original_two_zero_fields() {
    let fixture = Fixture::new();
    fixture
        .full_scope
        .require_root_prefix(&fixture.root_scope)
        .unwrap();
    let mut changed = fixture.root_scope;
    changed.provider_attempt = d(1);
    assert!(fixture.full_scope.require_root_prefix(&changed).is_err());
    for index in 0..5 {
        let mut changed = fixture.root_scope;
        match index {
            0 => changed.flight = d(1),
            1 => changed.original_source_session = d(1),
            2 => changed.mount_attempt = d(1),
            3 => changed.provider_acquisition = d(1),
            _ => changed.original_root_request = d(1),
        }
        assert!(
            fixture.full_scope.require_root_prefix(&changed).is_err(),
            "known field {index}"
        );
    }
}

#[test]
fn required_section_sets_reject_every_extra_tag_duplicate_and_order_change() {
    let fixture = Fixture::new();
    let control = fixture.root_prepared();
    for tag in [
        Tag::RootPrepared,
        Tag::NativeReply,
        Tag::StorageHeld,
        Tag::SourceArtifact,
        Tag::RootDispositionControl,
        Tag::RootDispositionAssertion,
        Tag::Settlement,
        Tag::RecoveryQuery,
        Tag::RootRecoveryControl,
        Tag::ProviderRecoveryState,
        Tag::StorageRecoveryState,
        Tag::RootRecoveryAssertion,
    ] {
        assert!(
            PreparedNativeHeldControlV1::new(
                Kind::RootPrepared,
                fixture.root_scope,
                zero(),
                vec![fixture.w(Owner::Root), section(tag, vec![1])],
                fixture.signer(Owner::Root)
            )
            .is_err(),
            "extra {tag:?}"
        );
    }
    let mut bytes = control.to_canonical_bytes();
    for index in [8, 11, 16, 288, 298] {
        let old = bytes[index];
        bytes[index] ^= 0x80;
        assert!(
            SignedNativeHeldControlV1::from_canonical_bytes(&bytes).is_err(),
            "mutation {index}"
        );
        bytes[index] = old;
    }
    bytes.push(0);
    assert!(SignedNativeHeldControlV1::from_canonical_bytes(&bytes).is_err());
    assert!(
        PreparedNativeHeldControlV1::new(
            Kind::RootPrepared,
            fixture.root_scope,
            zero(),
            vec![fixture.w(Owner::Root), fixture.w(Owner::Root)],
            fixture.signer(Owner::Root)
        )
        .is_err()
    );
}

#[test]
fn every_control_kind_rejects_missing_extra_and_reordered_sections() {
    let fixture = Fixture::new();
    let original = fixture.root_prepared();
    let closed = fixture.r(NativeHeldDispositionV1::Closed, true);
    let partial_closed = fixture.control(
        Kind::RootClosed,
        fixture.root_scope,
        original.digest(),
        vec![
            fixture.w(Owner::Root),
            section(Tag::RootPrepared, original.to_canonical_bytes()),
            section(
                Tag::RootDispositionAssertion,
                closed.to_canonical_bytes().unwrap().to_vec(),
            ),
        ],
    );
    let controls = fixture
        .hot()
        .into_iter()
        .chain(fixture.recovery())
        .chain([partial_closed]);

    for control in controls {
        let prepared = control.prepared();
        for index in 0..prepared.sections().len() {
            let mut missing = prepared.sections().to_vec();
            missing.remove(index);
            assert!(
                PreparedNativeHeldControlV1::new(
                    control.kind(),
                    *control.scope(),
                    control.predecessor(),
                    missing,
                    prepared.signer().clone(),
                )
                .is_err(),
                "{:?} missing section {index}",
                control.kind(),
            );
        }
        let extra_tag = (1..=13)
            .map(|tag| Tag::from_u16(tag).unwrap())
            .find(|tag| prepared.section(*tag).is_none())
            .unwrap();
        let mut extra = prepared.sections().to_vec();
        extra.push(section(extra_tag, vec![1]));
        extra.sort_by_key(NativeHeldSectionV1::tag);
        assert!(
            PreparedNativeHeldControlV1::new(
                control.kind(),
                *control.scope(),
                control.predecessor(),
                extra,
                prepared.signer().clone(),
            )
            .is_err(),
            "{:?} extra section",
            control.kind(),
        );
        if prepared.sections().len() > 1 {
            let mut reordered = prepared.sections().to_vec();
            reordered.swap(0, 1);
            assert!(
                PreparedNativeHeldControlV1::new(
                    control.kind(),
                    *control.scope(),
                    control.predecessor(),
                    reordered,
                    prepared.signer().clone(),
                )
                .is_err(),
                "{:?} reordered sections",
                control.kind(),
            );
        }
    }
}

#[test]
fn fixed_assertion_preimages_pin_stable_unsigned_identity_domains() {
    let fixture = Fixture::new();
    let assertion = fixture.r(NativeHeldDispositionV1::Accepted, false);
    let mut expected = b"AOSNDA01".to_vec();
    expected.extend_from_slice(&[0, 1, 1, 2, 0, 0, 0, 0]);
    for field in [
        fixture.full_scope.flight,
        fixture.full_scope.original_source_session,
        fixture.full_scope.mount_attempt,
        fixture.full_scope.provider_attempt,
        fixture.full_scope.provider_acquisition,
        fixture.full_scope.original_root_request,
        fixture.full_scope.original_native_request,
    ] {
        expected.extend_from_slice(field.as_bytes());
    }
    expected.extend_from_slice(&[90; 32]);
    expected.extend_from_slice(assertion.descriptor_commitment.as_bytes());
    for (record, key_length) in assertion.records.iter().zip([69_u16, 75, 64, 66]) {
        expected.extend_from_slice(&40_u16.to_be_bytes());
        expected.extend_from_slice(&key_length.to_be_bytes());
        expected.extend_from_slice(&[9; 32]);
        expected.extend_from_slice(record.key());
    }

    assert_eq!(expected.len(), 722);
    assert_eq!(assertion.to_canonical_bytes().unwrap().as_slice(), expected);
    let root_id = ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.native-held-completion.root-disposition.v1\0")
            .chain_update(&expected)
            .finalize()
            .into(),
    );
    assert_eq!(assertion.digest().unwrap(), root_id);
    let storage = fixture.storage_assertion(&assertion);
    let provider = fixture.provider_assertion(&assertion);
    for (bytes, domain, actual) in [
        (
            storage.to_canonical_bytes().unwrap().to_vec(),
            b"aos.sandbox.native-held-completion.storage-settlement.v1\0".as_slice(),
            storage.digest().unwrap(),
        ),
        (
            provider.to_canonical_bytes().unwrap().to_vec(),
            b"aos.sandbox.native-held-completion.provider-settlement.v1\0".as_slice(),
            provider.digest().unwrap(),
        ),
    ] {
        let independent = ObjectDigest::from_bytes(
            Sha256::new()
                .chain_update(domain)
                .chain_update(bytes)
                .finalize()
                .into(),
        );
        assert_eq!(actual, independent);
    }
}

#[test]
fn partial_closed_is_stable_across_signature_and_query_variations() {
    let fixture = Fixture::new();
    let original = fixture.root_prepared();
    let r = fixture.r(NativeHeldDispositionV1::Closed, true);
    let sections = vec![
        fixture.w(Owner::Root),
        section(Tag::RootPrepared, original.to_canonical_bytes()),
        section(
            Tag::RootDispositionAssertion,
            r.to_canonical_bytes().unwrap().to_vec(),
        ),
    ];
    let first = fixture.control(
        Kind::RootClosed,
        fixture.root_scope,
        original.digest(),
        sections.clone(),
    );
    let other = PreparedNativeHeldControlV1::new(
        Kind::RootClosed,
        fixture.root_scope,
        original.digest(),
        sections,
        fixture.signer(Owner::Root),
    )
    .unwrap()
    .with_signature([0xB2; 64]);

    assert_eq!(first.to_canonical_bytes().len(), 2998);
    assert_ne!(first.digest(), other.digest());
    assert_eq!(
        r.digest().unwrap(),
        RootNativeDispositionAssertionV1::from_canonical_bytes(
            first.section(Tag::RootDispositionAssertion).unwrap()
        )
        .unwrap()
        .digest()
        .unwrap()
    );
    assert_ne!(r.digest().unwrap(), first.digest());
    let mut invalid = r.clone();
    invalid.disposition = NativeHeldDispositionV1::Accepted;
    assert!(invalid.to_canonical_bytes().is_err());
    invalid = r;
    invalid.descriptor_commitment = d(1);
    assert!(invalid.to_canonical_bytes().is_err());
}

#[test]
fn descriptor_free_recovery_controls_roundtrip_inside_finite_bounds() {
    let fixture = Fixture::new();
    for control in fixture.recovery() {
        let bytes = control.to_canonical_bytes();
        let maximum = match control.kind() {
            Kind::RootRecoveryQuery => 5010,
            Kind::ProviderRecoveryState => 6785,
            Kind::ProviderStorageRecoveryQuery => 5650,
            Kind::StorageRecoveryState => 2942,
            _ => unreachable!(),
        };
        assert!(bytes.len() <= maximum);
        assert_eq!(
            SignedNativeHeldControlV1::from_canonical_bytes(&bytes).unwrap(),
            control
        );
    }
}

#[test]
fn recovery_query_golden_keeps_correlation_separate_from_original_scope() {
    let fixture = Fixture::new();
    let query = fixture.query(d(103), NativeHeldRecoveryModeV1::Observe);
    let mut expected = vec![100; 32];
    expected.extend_from_slice(&[101; 32]);
    expected.extend_from_slice(&102_u64.to_be_bytes());
    expected.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0, 0]);
    expected.extend_from_slice(&[103; 32]);
    expected.extend_from_slice(&[0; 32]);

    assert_eq!(query.to_canonical_bytes().unwrap().as_slice(), expected);
    assert_eq!(
        NativeHeldRecoveryQueryV1::from_canonical_bytes(&expected).unwrap(),
        query
    );
    let mut child = query;
    child.target = NativeHeldRecoveryTargetV1::NativeScope;
    child.parent_root_query = d(104);
    child.mode = NativeHeldRecoveryModeV1::RecordRootTerminal;
    assert!(
        child
            .validate_for_kind(Kind::ProviderStorageRecoveryQuery)
            .is_err()
    );
}

#[test]
fn wrong_current_child_parent_and_old_archive_nonce_are_not_joined() {
    let fixture = Fixture::new();
    let controls = fixture.recovery();
    let ten = &controls[1];
    let mut query =
        NativeHeldRecoveryQueryV1::from_canonical_bytes(ten.section(Tag::RecoveryQuery).unwrap())
            .unwrap();
    query.recovery_session = d(200);
    assert!(
        PreparedNativeHeldControlV1::new(
            Kind::ProviderRecoveryState,
            fixture.full_scope,
            ten.predecessor(),
            vec![
                section(
                    Tag::RecoveryQuery,
                    query.to_canonical_bytes().unwrap().to_vec()
                ),
                section(
                    Tag::ProviderRecoveryState,
                    ten.section(Tag::ProviderRecoveryState).unwrap().to_vec()
                )
            ],
            fixture.signer(Owner::Provider)
        )
        .is_err()
    );
    assert!(
        PreparedNativeHeldControlV1::new(
            Kind::ProviderRecoveryState,
            fixture.full_scope,
            d(201),
            ten.prepared().sections().to_vec(),
            fixture.signer(Owner::Provider)
        )
        .is_err()
    );
}

#[test]
fn runtime_only_recovery_does_not_overwrite_durable_phase_or_create_interest() {
    let fixture = Fixture::new();
    let twelve = &fixture.recovery()[3];
    let mut state = StorageNativeRecoveryStateV1::from_canonical_bytes(
        twelve.section(Tag::StorageRecoveryState).unwrap(),
    )
    .unwrap();
    state.fields.phase = 254;
    assert!(state.to_canonical_bytes().is_err());
    state.fields.phase = 4;
    state.fields.row_class = NativeHeldRecoveryRowClassV1::Absent;
    assert!(state.to_canonical_bytes().is_err());
    state.fields.row_class = NativeHeldRecoveryRowClassV1::Native;
    state.fields.child_status = NativeHeldRecoveryChildStatusV1::Unreachable;
    assert!(state.to_canonical_bytes().is_err());
}

#[test]
fn recovery_cannot_claim_acceptance_or_hot_signature_before_its_durable_phase() {
    let fixture = Fixture::new();
    let controls = fixture.recovery();
    let mut state = ProviderNativeRecoveryStateV1::from_canonical_bytes(
        controls[1].section(Tag::ProviderRecoveryState).unwrap(),
    )
    .unwrap();
    state.fields.phase = 8;
    assert!(state.to_canonical_bytes().is_err());
    state.fields.hot_terminal = None;
    state.to_canonical_bytes().unwrap();

    state.fields.phase = 1;
    state.fields.root_disposition = zero();
    state.fields.storage_settlement = zero();
    state.fields.provider_settlement = zero();
    state.fields.disposition = None;
    state.fields.own_assertion.clear();
    state.fields.child = None;
    state.fields.child_status = NativeHeldRecoveryChildStatusV1::NotQueried;
    assert!(state.to_canonical_bytes().is_err());
    state.fields.acceptance = zero();
    state.to_canonical_bytes().unwrap();
}

#[test]
fn recovery_unsigned_assertions_keep_observed_root_artifact_and_descriptor_exact() {
    let fixture = Fixture::new();
    let controls = fixture.recovery();
    let mut provider = ProviderNativeRecoveryStateV1::from_canonical_bytes(
        controls[1].section(Tag::ProviderRecoveryState).unwrap(),
    )
    .unwrap();
    let mut changed =
        ProviderNativeSettlementAssertionV1::from_canonical_bytes(&provider.fields.own_assertion)
            .unwrap();
    changed.source_artifact = d(222);
    provider.fields.provider_settlement = changed.digest().unwrap();
    provider.fields.own_assertion = changed.to_canonical_bytes().unwrap().to_vec();
    provider.fields.hot_terminal = None;
    assert!(provider.to_canonical_bytes().is_err());

    let mut storage = StorageNativeRecoveryStateV1::from_canonical_bytes(
        controls[3].section(Tag::StorageRecoveryState).unwrap(),
    )
    .unwrap();
    let root = storage.fields.disposition.as_mut().unwrap();
    root.descriptor_commitment = d(223);
    storage.fields.root_disposition = root.digest().unwrap();
    let mut changed =
        StorageNativeSettlementAssertionV1::from_canonical_bytes(&storage.fields.own_assertion)
            .unwrap();
    changed.root_disposition = storage.fields.root_disposition;
    storage.fields.storage_settlement = changed.digest().unwrap();
    storage.fields.own_assertion = changed.to_canonical_bytes().unwrap().to_vec();
    storage.fields.hot_terminal = None;
    assert!(storage.to_canonical_bytes().is_err());
}

#[test]
fn cold_closed_without_store_retains_unresolved_source_phase_and_zero_acceptance() {
    let fixture = Fixture::new();
    let r = fixture.r(NativeHeldDispositionV1::Closed, true);
    let fields = NativeHeldRecoveryFieldsV1 {
        phase: 7,
        runtime_status: NativeHeldRuntimeStatusV1::RecoveryOnly,
        row_class: NativeHeldRecoveryRowClassV1::Native,
        child_status: NativeHeldRecoveryChildStatusV1::NotQueried,
        diagnostic_sequence: 1,
        native_request: fixture.request.digest(),
        acceptance: zero(),
        root_disposition: r.digest().unwrap(),
        storage_settlement: zero(),
        provider_settlement: zero(),
        witness: Some(fixture.provider_witness.records[5].clone()),
        disposition: Some(r),
        own_assertion: Vec::new(),
        hot_terminal: None,
        child: None,
    };
    ProviderNativeRecoveryStateV1 {
        fields: fields.clone(),
    }
    .to_canonical_bytes()
    .unwrap();
    let mut fabricated = fields;
    fabricated.phase = 8;
    fabricated.storage_settlement = d(1);
    assert!(
        ProviderNativeRecoveryStateV1 { fields: fabricated }
            .to_canonical_bytes()
            .is_err()
    );
}

#[test]
fn suffix_preserves_prepared_signer_and_append_once_slots() {
    let fixture = Fixture::new();
    let one = fixture.root_prepared();
    let initial = NativeHeldCompletionSuffixV1::new(
        Owner::Root,
        0,
        fixture.root_scope.flight,
        Some(one.prepared().clone()),
        vec![],
    )
    .unwrap();
    let bytes = initial.to_canonical_bytes().unwrap();
    assert_eq!(
        NativeHeldCompletionSuffixV1::from_canonical_bytes(&bytes).unwrap(),
        initial
    );
    let source = NativeHeldCompletionSuffixV1::new(
        Owner::Provider,
        0,
        fixture.root_scope.flight,
        None,
        vec![one.clone()],
    )
    .unwrap();
    assert_eq!(
        NativeHeldCompletionSuffixV1::from_canonical_bytes(&source.to_canonical_bytes().unwrap())
            .unwrap(),
        source
    );
    assert!(
        NativeHeldCompletionSuffixV1::new(
            Owner::Provider,
            0,
            fixture.root_scope.flight,
            None,
            vec![one.clone(), one]
        )
        .is_err()
    );
    let mut invalid = bytes;
    invalid[11] = 254;
    assert!(NativeHeldCompletionSuffixV1::from_canonical_bytes(&invalid).is_err());

    let mut oversized = initial.to_canonical_bytes().unwrap();
    oversized[48..52].copy_from_slice(&8193_u32.to_be_bytes());
    assert!(NativeHeldCompletionSuffixV1::from_canonical_bytes(&oversized).is_err());
    oversized = initial.to_canonical_bytes().unwrap();
    oversized[52..54].copy_from_slice(&13_u16.to_be_bytes());
    assert!(NativeHeldCompletionSuffixV1::from_canonical_bytes(&oversized).is_err());
}

#[test]
fn storage_settled_first11_and12_archive_has_empty_preparation_and_fixed_slots() {
    let fixture = Fixture::new();
    let hot = fixture.hot();
    let recovery = fixture.recovery();
    let controls = vec![
        hot[0].clone(),
        hot[1].clone(),
        hot[4].clone(),
        hot[5].clone(),
        recovery[2].clone(),
        recovery[3].clone(),
    ];
    let after = NativeHeldCompletionSuffixV1::new(
        Owner::Storage,
        4,
        fixture.root_scope.flight,
        None,
        controls.clone(),
    )
    .unwrap();
    assert_eq!(
        NativeHeldCompletionSuffixV1::from_canonical_bytes(&after.to_canonical_bytes().unwrap())
            .unwrap(),
        after
    );
    assert!(
        NativeHeldCompletionSuffixV1::new(
            Owner::Storage,
            4,
            fixture.root_scope.flight,
            Some(recovery[3].prepared().clone()),
            controls
        )
        .is_err()
    );
    // Eligibility and removal of only these two slots belong to the actual
    // Storage before/after row reducer, not this nonauthorizing suffix parser.
    assert_eq!(MAXIMUM_NATIVE_HELD_SUFFIX_BYTES_V1, 106_648);
}

#[test]
fn record_byte_golden_has_fixed_family_and_no_invented_revision() {
    let value = witness(NativeHeldRecordFamilyV1::StorageIssuance, 3);
    let mut expected = vec![0, 6, 0, 48];
    expected.extend_from_slice(&[3; 32]);
    expected.extend_from_slice(&[3; 48]);
    assert_eq!(value.to_canonical_bytes(), expected);
    let mut hash_preimage = b"aos.sandbox.native-held-completion.record-bytes.v1\0".to_vec();
    hash_preimage.extend_from_slice(&[0, 6, 0, 48]);
    hash_preimage.extend_from_slice(&[3; 48]);
    hash_preimage.extend_from_slice(b"exact-canonical-row");
    let expected_digest = ObjectDigest::from_bytes(Sha256::digest(hash_preimage).into());
    assert_eq!(
        native_held_record_byte_digest_v1(
            NativeHeldRecordFamilyV1::StorageIssuance,
            value.key(),
            b"exact-canonical-row"
        )
        .unwrap(),
        expected_digest
    );
    assert!(
        NativeHeldByteWitnessV1::from_canonical_bytes(
            NativeHeldRecordFamilyV1::ProviderNative,
            &expected
        )
        .is_err()
    );
}

#[test]
fn cryptographic_check_does_not_accept_control_nominated_expected_pin() {
    let fixture = Fixture::new();
    let prepared = fixture.root_prepared().prepared().clone();
    let key = SigningKey::from_bytes(&[51; 32]);
    let signed = prepared
        .clone()
        .with_signature(key.sign(&prepared.signature_message()).to_bytes());
    signed
        .verify_signature_claim(
            &fixture.signer(Owner::Root),
            &key.verifying_key().to_bytes(),
        )
        .unwrap();
    assert!(
        signed
            .verify_signature_claim(
                &fixture.signer(Owner::Provider),
                &key.verifying_key().to_bytes()
            )
            .is_err()
    );
    assert!(
        signed
            .verify_signature_claim(
                &fixture.signer(Owner::Root),
                &SigningKey::from_bytes(&[200; 32])
                    .verifying_key()
                    .to_bytes()
            )
            .is_err()
    );
}
