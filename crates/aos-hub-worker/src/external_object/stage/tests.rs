//! Signed issuer fixtures for private staging, concurrent parts and closure.

use std::cell::RefCell;

use aos_hub_core::storage_authority::{
    control::StorageAuthorityPublication, lease::*, ApproveStorageAuthorityAlias,
    AssociateStorageAuthorityBinding, AttestStorageAuthorityExclusivity,
    CreatePhysicalStorageAuthority, PhysicalStorageAuthorityId, SetStorageAuthorityAdmission,
    StorageAuthorityAdmissionState, StorageAuthorityAliasSpec, StorageAuthorityCredentialMember,
    StorageAuthorityHost,
};
use aos_hub_core::storage_work::StorageWorkKey;
use ed25519_dalek::SigningKey;

use super::super::{config::Config, protocol, state::Head};
use super::{
    config::{Config as StageConfig, Domain, ProviderContract},
    protocol::{Intent, Receipt, SourceProof, Turn},
    state,
};
use aos_hub_core::direct_upload::*;
use aos_hub_core::storage_authority::{
    external_object::stage::{
        ExternalStageContext, ExternalStageOperation as Operation, ExternalStageOutcome as Outcome,
    },
    GuardIncarnation, StorageGuardStamp,
};

const EXECUTOR: &str = "qualified-executor";
const KEY_ID: &str = "external-issuer-one";

fn integer(value: i64) -> LeaseInteger {
    LeaseInteger::new(value).unwrap()
}

fn clock(value: i64) -> LeaseClock {
    LeaseClock {
        observed_at: value,
        uncertainty: 2,
    }
}

fn profile() -> LeaseTimingProfile {
    // Fixture-only example; these values are not a qualified deployment default.
    LeaseTimingProfile {
        profile_id: "fixture-reviewed-clock".into(),
        review_digest: "9".repeat(64),
        maximum_lifetime: integer(30),
        maximum_clock_uncertainty: integer(2),
    }
}

fn publication() -> StorageAuthorityPublication {
    let authority_id =
        PhysicalStorageAuthorityId::parse("00000000-0000-4000-8000-000000000001").unwrap();
    let authority = CreatePhysicalStorageAuthority {
        authority_id: authority_id.clone(),
        guard_namespace_id: "permanent-guard-namespace".into(),
        physical_resource_evidence_digest: "1".repeat(64),
        qualification_digest: "2".repeat(64),
        qualified_managed_prefix: "managed".into(),
    };
    let alias = ApproveStorageAuthorityAlias {
        alias_id: "alias-one".into(),
        authority_id: authority_id.clone(),
        spec: StorageAuthorityAliasSpec {
            host: StorageAuthorityHost::Dns("objects.example.invalid".into()),
            port: 443,
            bucket: "qualified-bucket".into(),
        },
        equivalence_evidence_digest: "3".repeat(64),
    };
    let association = AssociateStorageAuthorityBinding {
        association_id: "association-one".into(),
        authority_id: authority_id.clone(),
        alias_id: alias.alias_id.clone(),
        binding_id: 9_007_199_254_740_993,
        binding_stable_id: "binding-one".into(),
        binding_resource_version: 9_007_199_254_740_995,
        binding_write_revision: 9_007_199_254_740_997,
        binding_prefix: "managed/binding".into(),
    };
    let credentials = ["delete", "list", "presign", "read", "write"]
        .into_iter()
        .map(|purpose| StorageAuthorityCredentialMember {
            association_id: association.association_id.clone(),
            purpose: purpose.into(),
            generation: 9_007_199_254_741_001,
            secret_version_ref: format!("secret://fixture/{purpose}/immutable-v1"),
            credential_fingerprint: "4".repeat(64),
        })
        .collect();
    let attestation = AttestStorageAuthorityExclusivity {
        attestation_id: "attestation-one".into(),
        authority_id: authority_id.clone(),
        managed_prefix: "managed".into(),
        qualification_digest: authority.qualification_digest.clone(),
        provider_policy_evidence_digest: "5".repeat(64),
        executor_identity: EXECUTOR.into(),
        credentials,
        valid_until: 1000,
    };
    let admission = SetStorageAuthorityAdmission {
        authority_id,
        expected_generation: 0,
        expected_digest: None,
        guard_namespace_id: authority.guard_namespace_id.clone(),
        state: StorageAuthorityAdmissionState::Admitted,
        attestation_id: Some(attestation.attestation_id.clone()),
        association_ids: vec![association.association_id.clone()],
    };
    let digest = protocol::digest(&admission).unwrap();
    let publication = StorageAuthorityPublication {
        authority,
        aliases: vec![alias],
        associations: vec![association],
        attestation: Some(attestation),
        admission,
        generation: 1,
        digest,
    };
    publication
        .validate(&publication.authority.guard_namespace_id, EXECUTOR)
        .unwrap();
    publication
}

fn config() -> Config {
    let publication = publication();
    let write = LeaseCohort::from_publication(
        &publication,
        EXECUTOR,
        "association-one",
        LeasePurpose::Write,
        "managed/binding",
        vec![
            LeaseEffect::Put,
            LeaseEffect::MultipartCreate,
            LeaseEffect::MultipartPart,
            LeaseEffect::MultipartComplete,
            LeaseEffect::MultipartAbort,
        ],
    )
    .unwrap();
    let read = LeaseCohort::from_publication(
        &publication,
        EXECUTOR,
        "association-one",
        LeasePurpose::Read,
        "managed/binding",
        vec![LeaseEffect::Head, LeaseEffect::Read],
    )
    .unwrap();
    let value = Config {
        version: 1,
        guard_namespace_id: publication.authority.guard_namespace_id.clone(),
        executor_identity: EXECUTOR.into(),
        issuer_key_id: KEY_ID.into(),
        issuer_public_key: hex::encode(SigningKey::from_bytes(&[7; 32]).verifying_key().as_bytes()),
        timing_profile: profile(),
        clock_uncertainty: 2,
        aliases: publication.aliases.clone(),
        cohorts: vec![write, read],
        publications: vec![publication],
    };
    value.validate().unwrap();
    value
}

async fn token(config: &Config, index: usize, previous_sequence: i64) -> Vec<u8> {
    token_at(config, index, previous_sequence, 100).await
}

async fn token_at(config: &Config, index: usize, previous_sequence: i64, at: i64) -> Vec<u8> {
    let publication = &config.publications[0];
    let mut journal = EpochLeaseIssuerJournal::initialize_fresh_namespace(
        publication,
        EXECUTOR,
        BoundedLeaseRevocationPolicy {
            timing_profile: profile(),
        },
        clock(at),
    )
    .unwrap();
    // Fixture models the exact retained issuer state before a new actual CAS.
    journal.last_sequence = integer(previous_sequence);
    if previous_sequence > 0 {
        journal.largest_issued_expiry = integer(at + 30);
    }
    let live = RefCell::new(journal);
    let prepared = live
        .borrow()
        .prepare_issue(
            publication,
            config.cohorts[index].clone(),
            KEY_ID,
            at + 30,
            clock(at),
        )
        .unwrap();
    let key = EpochLeaseSigningKey::from_bytes(KEY_ID.into(), &[7; 32]).unwrap();
    prepared
        .commit_and_sign(
            &key,
            |transition| {
                let live = &live;
                async move {
                    anyhow::ensure!(
                        *live.borrow() == transition.expected,
                        "fixture issuer CAS changed"
                    );
                    *live.borrow_mut() = transition.next;
                    Ok(())
                }
            },
            || Ok(clock(at)),
        )
        .await
        .unwrap()
}

const DEPLOYMENT: &str = "fixture-deployment";

fn context(object: &Config, count: u32) -> ExternalStageContext {
    let association = &object.cohorts[0].association;
    let credential = |purpose: &str| DirectCredentialRevision {
        purpose: purpose.into(),
        credential_id: format!("credential-{purpose}"),
        generation: WireInteger::new(9_007_199_254_741_001),
        secret_version_ref: format!("secret://fixture/{purpose}/immutable-v1"),
        credential_fingerprint: "4".repeat(64),
    };
    let bytes = if count == 0 {
        0
    } else if count == 1 {
        3
    } else {
        u64::from(count) * 8 * 1024 * 1024
    };
    let mut value = ExternalStageContext {
        deployment_id: DEPLOYMENT.into(),
        session_id: "retained-session-one".into(),
        principal_id: "principal-one".into(),
        logical_fingerprint: "a".repeat(64),
        logical_expires_at: WireInteger::new(1000),
        intent: DirectUploadIntent {
            version: 1,
            client_operation_id: "8".repeat(64),
            target: DirectUploadTarget::CacheObject {
                cache_id: "cache-one".into(),
                path: "blob".into(),
            },
            expected_sha256: if count == 0 {
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into()
            } else {
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".into()
            },
            byte_size: WireInteger::new(bytes),
            part_size: WireInteger::new(8 * 1024 * 1024),
            dependency_phase: DirectDependencyPhase::Content,
            transfer_mode: DirectTransferMode::DirectRequired,
        },
        placement: DirectPlacement {
            placement_id: WireInteger::new(1),
            placement_resource_version: WireInteger::new(2),
            write_spec_version: WireInteger::new(3),
            binding_id: WireInteger::new(association.binding_id.get() as u64),
            binding_resource_version: WireInteger::new(
                association.binding_resource_version.get() as u64
            ),
            binding_write_revision: WireInteger::new(
                association.binding_write_revision.get() as u64
            ),
            final_key: "managed/binding/final/blob".into(),
            staging_prefix: "managed/binding/.aos-direct-upload".into(),
            private_stage_policy: DirectPrivateStagePolicyRef {
                policy_id: "private-stage-policy".into(),
                policy_digest: "6".repeat(64),
                namespace: "private-stage-namespace".into(),
            },
            protected_profile_digest: String::new(),
            checksum_algorithm: DirectChecksumAlgorithm::Md5,
            physical: DirectPhysicalContext::External {
                write_cohort: Box::new(object.cohorts[0].clone()),
                read_cohort: Box::new(object.cohorts[1].clone()),
            },
            write_credential: credential("write"),
            read_credential: credential("read"),
            presign_credential: credential("presign"),
        },
    };

    let stage = staging(object, &value);
    value.placement.protected_profile_digest = protected_profile(object, &stage.domains[0])
        .digest()
        .unwrap();
    value.validate().unwrap();
    value
}

fn protected_profile(object: &Config, domain: &Domain) -> DirectProtectedProfile {
    let external = DirectExternalStorageCapabilities {
        selector: DirectExternalProfileSelector {
            physical_authority_id: domain.write_cohort.authority.authority_id.clone(),
            association: domain.write_cohort.association.clone(),
            write_credential: domain.write_credential.clone(),
            read_credential: domain.read_credential.clone(),
            presign_credential: domain.presign_credential.clone(),
        },
        issuer_installation: domain.issuer_installation.clone(),
        issuer_key_id: object.issuer_key_id.clone(),
        issuer_public_key: object.issuer_public_key.clone(),
        write_cohort: domain.write_cohort.clone(),
        read_cohort: domain.read_cohort.clone(),
        private_stage_policy: domain.private_stage_policy.clone(),
        staging_prefix: domain.staging_prefix.clone(),
        checksum_algorithm: domain.checksum_algorithm,
        maximum_grant_lifetime: domain.maximum_grant_lifetime,
        provider_contract_id: domain.provider_contract.contract_id.clone(),
        provider_contract_evidence_digest: domain.provider_contract.evidence_digest.clone(),
        timing_profile: object.timing_profile.clone(),
        clock_uncertainty: integer(object.clock_uncertainty),
    };

    // Static test reference; these bounds establish no provider or runtime qualification.
    let runtime = DirectRuntimeQualification {
        version: 1,
        qualification_digest: "8".repeat(64),
        maximum_object_bytes: WireInteger::new(MAX_DIRECT_OBJECT_BYTES),
        maximum_verification_seconds: WireInteger::new(10),
        settlement_reserve_seconds: WireInteger::new(8),
        maximum_parallel_objects: WireInteger::new(4),
        maximum_parallel_provider_requests: WireInteger::new(8),
        cache_destination_policy: DirectCacheDestinationPolicy::RetainedOriginalBaseline,
    };
    DirectProtectedProfile::external(external, runtime).unwrap()
}

fn staging(object: &Config, context: &ExternalStageContext) -> StageConfig {
    let value = StageConfig {
        version: 1,
        domains: vec![Domain {
            issuer_installation:
                aos_hub_core::storage_authority::lease::control::IssuerInstallation {
                    format_version: 1,
                    authority: object.publications[0].authority.clone(),
                    issuer_resource_id: "permanent-fixture-issuer".into(),
                    runtime_identity: "fixture-runtime".into(),
                    executor_identity: EXECUTOR.into(),
                },
            publication: object.publications[0].clone(),
            write_cohort: object.cohorts[0].clone(),
            read_cohort: object.cohorts[1].clone(),
            write_credential: context.placement.write_credential.clone(),
            read_credential: context.placement.read_credential.clone(),
            presign_credential: context.placement.presign_credential.clone(),
            private_stage_policy: context.placement.private_stage_policy.clone(),
            staging_prefix: context.placement.staging_prefix.clone(),
            maximum_grant_lifetime: WireInteger::new(300),
            checksum_algorithm: DirectChecksumAlgorithm::Md5,
            provider_contract: ProviderContract {
                contract_id: "fixture-qualified-private-provider".into(),
                evidence_digest: "7".repeat(64),
                private_completed_stage: true,
                completed_upload_id_rejects_late_parts: true,
                multipart_abort_closes_upload_id: true,
                multipart_copy_from_immutable_source: true,
                upload_part_checksum_enforced: true,
            },
        }],
    };
    value.validate(object).unwrap();
    value
}

struct Fixture {
    object: Config,
    config: StageConfig,
    context: ExternalStageContext,
    write: Vec<u8>,
    read: Vec<u8>,
}

impl Fixture {
    async fn new(count: u32) -> Self {
        let object = config();
        let context = context(&object, count);
        let config = staging(&object, &context);
        let write = token(&object, 0, 0).await;
        let read = token(&object, 1, 1).await;
        Self {
            object,
            config,
            context,
            write,
            read,
        }
    }

    fn intent(&self, id: &str, operation: Operation) -> Intent {
        Intent {
            operation_id: id.into(),
            context: self.context.clone(),
            operation,
        }
    }

    fn fresh(&self, destination: bool) -> Head {
        let scope = self.context.scope(destination).unwrap();
        Head {
            version: 1,
            scope: scope.clone(),
            configuration: protocol::digest(&self.object).unwrap(),
            floor: EpochLeaseFloor::initialize_fresh_guard(
                self.object.cohorts[0].authority.clone(),
                EXECUTOR.into(),
                scope.full_key,
                &profile(),
                clock(100),
            )
            .unwrap(),
            pending: None,
            observation: None,
            visible_receipt: None,
            receipts: integer(0),
            incarnation: WireInteger::new(0),
            stage: None,
        }
    }

    fn begin(
        &self,
        head: &Head,
        intent: Intent,
        source: Option<SourceProof>,
        retained: Option<Turn>,
    ) -> anyhow::Result<(Head, Turn)> {
        state::begin(
            head,
            &self.object,
            &self.config,
            intent,
            aos_hub_core::storage_authority::external_object::stage::ExternalStageAdmissionMode::Fresh,
            None,
            &self.write,
            &self.read,
            "b".repeat(64),
            source,
            retained,
            clock(102),
        )
    }

    fn terminal(&self, head: &Head, turn: Turn, outcome: Outcome) -> (Head, Receipt) {
        let receipt = Receipt { turn, outcome };
        let next = state::terminal(head, &self.config, &receipt).unwrap();
        (next, receipt)
    }

    fn stamp(&self, turn: &Turn) -> StorageGuardStamp {
        StorageGuardStamp {
            physical_authority_id: self.context.scope(false).unwrap().physical_authority_id,
            incarnation: GuardIncarnation::parse(turn.expected_incarnation.get().to_string())
                .unwrap(),
        }
    }

    fn part(&self, number: u32) -> DirectPart {
        let (offset, bytes) = self.context.intent.part_range(number).unwrap();
        DirectPart {
            part_number: number,
            offset: WireInteger::new(offset),
            byte_size: WireInteger::new(bytes),
            sha256: self.context.intent.expected_sha256.clone(),
            checksum: DirectPartChecksum {
                algorithm: DirectChecksumAlgorithm::Md5,
                value: "kAFQmDzST7DWlj99KOF/cg==".into(),
            },
        }
    }

    fn manifest(&self) -> (DirectManifestCommitment, Vec<DirectManifestPart>) {
        let parts: Vec<_> = (1..=self.context.intent.part_count().unwrap())
            .map(|number| DirectManifestPart {
                part: self.part(number),
                etag: format!("\"part-{number}\""),
            })
            .collect();
        let placement = self.context.placement.public_ref(DEPLOYMENT).unwrap();
        let manifest = DirectManifestCommitment {
            manifest_digest: canonical_manifest_digest(&self.context.intent, &placement, &parts)
                .unwrap(),
            placement,
            part_count: parts.len() as u32,
        };
        (manifest, parts)
    }

    fn closed_source(&self) -> (Head, Receipt) {
        let (head, create) = self
            .begin(
                &self.fresh(false),
                self.intent("create-stage", Operation::CreateStage),
                None,
                None,
            )
            .unwrap();
        if self.context.intent.byte_size.get() == 0 {
            let stamp = self.stamp(&create);
            return self.terminal(
                &head,
                create,
                Outcome::EmptyClosed {
                    etag: "\"empty\"".into(),
                    guard_stamp: stamp,
                },
            );
        }
        let (head, _) = self.terminal(
            &head,
            create,
            Outcome::Created {
                upload_id: "source-upload".into(),
            },
        );
        let (manifest, parts) = self.manifest();
        let mut head = head;
        for (index, chunk) in parts.chunks(64).enumerate() {
            let first_part = index as u32 * 64 + 1;
            let (pending, freeze) = self
                .begin(
                    &head,
                    self.intent(
                        &format!("freeze-stage-{index}"),
                        Operation::FreezeParts {
                            upload_id: "source-upload".into(),
                            manifest: manifest.clone(),
                            first_part,
                            parts: chunk.to_vec(),
                        },
                    ),
                    None,
                    None,
                )
                .unwrap();
            head = self
                .terminal(
                    &pending,
                    freeze,
                    Outcome::Frozen {
                        part_count: first_part - 1 + chunk.len() as u32,
                    },
                )
                .0;
        }
        let (head, close) = self
            .begin(
                &head,
                self.intent(
                    "close-stage",
                    Operation::CompleteStage {
                        upload_id: "source-upload".into(),
                        manifest,
                    },
                ),
                None,
                None,
            )
            .unwrap();
        let stamp = self.stamp(&close);
        self.terminal(
            &head,
            close,
            Outcome::Closed {
                upload_id: "source-upload".into(),
                etag: "\"closed\"".into(),
                guard_stamp: stamp,
            },
        )
    }

    fn verified_source(&self) -> SourceProof {
        let (head, closed) = self.closed_source();
        let close_receipt_digest = protocol::digest(&closed).unwrap();
        let (head, turn) = self
            .begin(
                &head,
                self.intent(
                    "verify-stage",
                    Operation::VerifyClosedStage {
                        upload_id: if self.context.intent.byte_size.get() == 0 {
                            None
                        } else {
                            Some("source-upload".into())
                        },
                        close_receipt_digest: close_receipt_digest.clone(),
                    },
                ),
                None,
                None,
            )
            .unwrap();
        let (head, verified) = self.terminal(
            &head,
            turn,
            Outcome::Verified {
                sha256: self.context.intent.expected_sha256.clone(),
                byte_size: self.context.intent.byte_size,
                close_receipt_digest,
            },
        );
        let proof = SourceProof {
            closed,
            verified,
            floor: head.floor,
            configuration: protocol::digest(&self.config).unwrap(),
        };
        proof
            .validate(&self.context, &protocol::digest(&proof.verified).unwrap())
            .unwrap();
        proof
    }

    fn destination(&self) -> (Head, SourceProof) {
        let proof = self.verified_source();
        let digest = protocol::digest(&proof.verified).unwrap();
        let (head, create) = self
            .begin(
                &self.fresh(true),
                self.intent(
                    "create-destination",
                    Operation::CreateDestination {
                        verified_stage_receipt_digest: digest,
                    },
                ),
                Some(proof.clone()),
                None,
            )
            .unwrap();
        let (head, _) = self.terminal(
            &head,
            create,
            Outcome::Created {
                upload_id: "destination-upload".into(),
            },
        );
        (head, proof)
    }

    fn copy_intent(&self, proof: &SourceProof, number: u32) -> Intent {
        self.intent(
            &format!("copy-part-{number}"),
            Operation::CopyDestinationPart {
                upload_id: "destination-upload".into(),
                verified_stage_receipt_digest: protocol::digest(&proof.verified).unwrap(),
                part: self.part(number),
            },
        )
    }
}

#[tokio::test]
async fn unknown_create_never_regenerates_permit_or_allows_other_turn() {
    let f = Fixture::new(1).await;
    let intent = f.intent("create", Operation::CreateStage);
    let (head, _) = f
        .begin(&f.fresh(false), intent.clone(), None, None)
        .unwrap();
    assert!(f.begin(&head, intent, None, None).is_err());
    assert!(f
        .begin(&head, f.intent("other", Operation::CreateStage), None, None)
        .is_err());
    let restored: Head = serde_json::from_slice(&serde_json::to_vec(&head).unwrap()).unwrap();
    assert!(f
        .begin(
            &restored,
            f.intent("create", Operation::CreateStage),
            None,
            None
        )
        .is_err());
}

#[tokio::test]
async fn exact_closed_read_retries_original_turn_without_repeating_close() {
    let f = Fixture::new(1).await;
    let (head, closed) = f.closed_source();
    let intent = f.intent(
        "verify",
        Operation::VerifyClosedStage {
            upload_id: Some("source-upload".into()),
            close_receipt_digest: protocol::digest(&closed).unwrap(),
        },
    );
    let (head, original) = f.begin(&head, intent.clone(), None, None).unwrap();
    let (retried, exact) = f.begin(&head, intent, None, None).unwrap();
    assert!(exact == original);
    assert!(retried.stage.as_ref().unwrap().pending.as_ref() == Some(&original));
    assert!(f
        .begin(
            &head,
            f.intent("changed", original.intent.operation.clone()),
            None,
            None
        )
        .is_err());
}

#[tokio::test]
async fn real_empty_put_has_permanent_incarnation_and_verified_zero_bytes() {
    let f = Fixture::new(0).await;
    let proof = f.verified_source();
    assert!(matches!(proof.closed.outcome, Outcome::EmptyClosed { .. }));
    assert!(
        matches!(proof.verified.outcome, Outcome::Verified { byte_size, .. } if byte_size.get() == 0)
    );
    assert_eq!(proof.closed.turn.expected_incarnation.get(), 1);
}

#[tokio::test]
async fn concurrent_parts_complete_out_of_order_then_exclusive_complete() {
    let f = Fixture::new(4).await;
    let (mut head, proof) = f.destination();
    let mut turns = Vec::new();
    for number in 1..=4 {
        let (next, turn) = f
            .begin(
                &head,
                f.copy_intent(&proof, number),
                Some(proof.clone()),
                None,
            )
            .unwrap();
        head = next;
        turns.push(turn);
    }
    assert_eq!(head.stage.as_ref().unwrap().pending_parts.len(), 4);
    let (manifest, _) = f.manifest();
    let complete = f.intent(
        "complete-destination",
        Operation::CompleteDestination {
            verified_stage_receipt_digest: protocol::digest(&proof.verified).unwrap(),
            upload_id: "destination-upload".into(),
            manifest,
        },
    );
    assert!(f
        .begin(&head, complete.clone(), Some(proof.clone()), None)
        .is_err());
    for index in [2, 0, 3, 1] {
        let turn = turns[index].clone();
        head = f
            .terminal(
                &head,
                turn,
                Outcome::Copied {
                    part: f.part(index as u32 + 1),
                    etag: format!("\"copy-{index}\""),
                },
            )
            .0;
    }
    assert_eq!(head.stage.as_ref().unwrap().frozen_parts, 4);
    assert!(f.begin(&head, complete, Some(proof), None).is_ok());
}

#[tokio::test]
async fn sixty_four_part_bound_keeps_compact_head_and_refuses_sixty_fifth() {
    let f = Fixture::new(65).await;
    let (mut head, proof) = f.destination();
    for number in 1..=64 {
        head = f
            .begin(
                &head,
                f.copy_intent(&proof, number),
                Some(proof.clone()),
                None,
            )
            .unwrap()
            .0;
    }
    assert_eq!(head.stage.as_ref().unwrap().pending_parts.len(), 64);
    assert!(serde_json::to_vec(&head).unwrap().len() <= protocol::MAX_MESSAGE);
    assert!(f
        .begin(&head, f.copy_intent(&proof, 65), Some(proof), None)
        .is_err());
}

#[tokio::test]
async fn unknown_copy_reuses_only_exact_durable_turn_and_bytes() {
    let f = Fixture::new(2).await;
    let (head, proof) = f.destination();
    let intent = f.copy_intent(&proof, 1);
    let (head, turn) = f
        .begin(&head, intent.clone(), Some(proof.clone()), None)
        .unwrap();
    assert!(f
        .begin(&head, intent.clone(), Some(proof.clone()), None)
        .is_err());
    let (same, replay) = f
        .begin(
            &head,
            intent.clone(),
            Some(proof.clone()),
            Some(turn.clone()),
        )
        .unwrap();
    assert!(replay == turn);
    assert_eq!(same.stage.as_ref().unwrap().pending_parts.len(), 1);
    let mut changed = intent;
    if let Operation::CopyDestinationPart { part, .. } = &mut changed.operation {
        part.sha256 = "d".repeat(64);
    }
    assert!(f.begin(&head, changed, Some(proof), Some(turn)).is_err());
}

#[tokio::test]
async fn historical_part_receipt_preserves_other_pending_turns_and_count() {
    let f = Fixture::new(2).await;
    let (head, proof) = f.destination();
    let (head, first) = f
        .begin(&head, f.copy_intent(&proof, 1), Some(proof.clone()), None)
        .unwrap();
    let (head, second) = f
        .begin(&head, f.copy_intent(&proof, 2), Some(proof), None)
        .unwrap();
    let (head, receipt) = f.terminal(
        &head,
        first,
        Outcome::Copied {
            part: f.part(1),
            etag: "\"copy-one\"".into(),
        },
    );
    let replay = state::replay(&head, &f.config, &receipt.turn.intent, &receipt).unwrap();
    assert_eq!(replay.stage.as_ref().unwrap().frozen_parts, 1);
    assert_eq!(replay.stage.as_ref().unwrap().pending_parts.len(), 1);
    assert!(
        replay.stage.as_ref().unwrap().pending_parts[0]
            == state::PartTurnRef::from_turn(&second).unwrap()
    );
}

#[tokio::test]
async fn pending_parts_block_abort_and_original_eligibility_cannot_renew() {
    let f = Fixture::new(2).await;
    let (head, proof) = f.destination();
    let (head, _) = f
        .begin(&head, f.copy_intent(&proof, 1), Some(proof.clone()), None)
        .unwrap();
    let abort = f.intent(
        "abort",
        Operation::AbortDestination {
            upload_id: "destination-upload".into(),
            verified_stage_receipt_digest: protocol::digest(&proof.verified).unwrap(),
        },
    );
    assert!(f.begin(&head, abort, Some(proof), None).is_err());
    let mut expired = f.intent("new-create", Operation::CreateStage);
    expired.context.logical_expires_at = WireInteger::new(102);
    assert!(f.begin(&f.fresh(false), expired, None, None).is_err());
}

#[tokio::test]
async fn source_digest_policy_and_closed_owner_forks_reject() {
    let f = Fixture::new(1).await;
    let proof = f.verified_source();
    let expected = protocol::digest(&proof.verified).unwrap();
    let mut changed = proof.clone();
    changed.configuration = "e".repeat(64);
    let intent = f.intent(
        "destination",
        Operation::CreateDestination {
            verified_stage_receipt_digest: expected.clone(),
        },
    );
    assert!(f
        .begin(&f.fresh(true), intent, Some(changed), None)
        .is_err());
    let mut changed = proof.clone();
    changed.closed.turn.intent.context.session_id = "forked-session".into();
    assert!(changed.validate(&f.context, &expected).is_err());
    let mut changed = proof;
    changed.verified.outcome = Outcome::Verified {
        sha256: "e".repeat(64),
        byte_size: f.context.intent.byte_size,
        close_receipt_digest: protocol::digest(&changed.closed).unwrap(),
    };
    assert!(changed.validate(&f.context, &expected).is_err());
}

#[tokio::test]
async fn incarnation_exhaustion_refuses_create_before_provider_allocation() {
    let f = Fixture::new(1).await;
    let mut head = f.fresh(false);
    head.incarnation = WireInteger::new(state::MAX_INCARNATION);
    assert!(f
        .begin(
            &head,
            f.intent("create", Operation::CreateStage),
            None,
            None
        )
        .is_err());
}

#[tokio::test]
async fn configured_provider_closure_flags_are_individually_required() {
    let f = Fixture::new(1).await;
    for index in 0..5 {
        let mut config = f.config.clone();
        let provider = &mut config.domains[0].provider_contract;
        match index {
            0 => provider.private_completed_stage = false,
            1 => provider.completed_upload_id_rejects_late_parts = false,
            2 => provider.multipart_abort_closes_upload_id = false,
            3 => provider.multipart_copy_from_immutable_source = false,
            _ => provider.upload_part_checksum_enforced = false,
        }
        assert!(config.validate(&f.object).is_err());
    }
}

#[tokio::test]
async fn original_deployment_and_complete_binding_write_revision_are_pinned() {
    let f = Fixture::new(1).await;
    let mut changed = f.context.clone();
    changed.placement.binding_write_revision = WireInteger::new(1);
    assert!(changed.validate().is_err());
    let actor_slot = DirectActorSlot {
        kind: DirectActorKind::User,
        numeric_id: WireInteger::new(1),
        incarnation: "00000000-0000-4000-8000-000000000001".into(),
    };
    let mut admission = DirectUploadAdmission {
        session_id: f.context.session_id.clone(),
        principal_id: actor_slot.principal_id(DEPLOYMENT).unwrap(),
        actor_slot,
        logical_fingerprint: String::new(),
        intent: f.context.intent.clone(),
        expires_at: f.context.logical_expires_at,
        placements: vec![f.context.placement.clone()],
    };
    admission.logical_fingerprint = admission.fingerprint(DEPLOYMENT).unwrap();
    let selected =
        ExternalStageContext::from_admission(&admission, WireInteger::new(1), DEPLOYMENT).unwrap();
    let mut expected = f.context.clone();
    expected.principal_id = admission.principal_id.clone();
    expected.logical_fingerprint = admission.logical_fingerprint.clone();
    assert!(selected == expected);
    assert!(ExternalStageContext::from_admission(
        &admission,
        WireInteger::new(1),
        "wrong-deployment"
    )
    .is_err());
}

#[tokio::test]
async fn application_domain_canonical_shape_and_body_bound_are_closed() {
    use aos_hub_core::storage_authority::external_object::stage::{
        ExternalStageRequest, MAX_EXTERNAL_STAGE_REQUEST_BYTES,
    };
    let f = Fixture::new(1).await;
    let key = StorageWorkKey::new([3; 32]).unwrap();
    let work = ExternalStageRequest::new(
        DEPLOYMENT.into(),
        "retained-create".into(),
        WireInteger::new(100),
        WireInteger::new(130),
        f.context.clone(),
        String::from_utf8(f.write).unwrap(),
        String::from_utf8(f.read).unwrap(),
        Operation::CreateStage,
    );
    let (body, signature) = work.sign(&key, DEPLOYMENT, 102).unwrap();
    assert!(ExternalStageRequest::authenticate(&key, &signature, &body, DEPLOYMENT, 102).is_ok());
    assert!(ExternalStageRequest::authenticate(
        &key,
        &key.sign_body(&body).unwrap(),
        &body,
        DEPLOYMENT,
        102
    )
    .is_err());
    assert!(ExternalStageRequest::authenticate(
        &key,
        &signature,
        &body,
        "different-deployment",
        102
    )
    .is_err());
    assert!(ExternalStageRequest::authenticate(&key, &signature, &body, DEPLOYMENT, 130).is_err());
    let mut unknown: serde_json::Value = serde_json::from_slice(&body).unwrap();
    unknown
        .as_object_mut()
        .unwrap()
        .insert("provider_url".into(), "https://attacker.invalid".into());
    let unknown = serde_json::to_vec(&unknown).unwrap();
    let signature = key
        .sign_body(
            &[
                b"aos.external-stage-control-auth.v1\0".as_slice(),
                unknown.as_slice(),
            ]
            .concat(),
        )
        .unwrap();
    assert!(
        ExternalStageRequest::authenticate(&key, &signature, &unknown, DEPLOYMENT, 102).is_err()
    );
    let excessive = vec![0; MAX_EXTERNAL_STAGE_REQUEST_BYTES + 1];
    assert!(
        ExternalStageRequest::authenticate(&key, "invalid", &excessive, DEPLOYMENT, 102).is_err()
    );
}

#[tokio::test]
async fn corrupted_pending_incarnation_rejects_before_terminal_replay() {
    let f = Fixture::new(0).await;
    let (mut head, turn) = f
        .begin(
            &f.fresh(false),
            f.intent("empty", Operation::CreateStage),
            None,
            None,
        )
        .unwrap();
    head.stage
        .as_mut()
        .unwrap()
        .pending
        .as_mut()
        .unwrap()
        .expected_incarnation = WireInteger::new(9);
    assert!(head
        .validate(&f.object, &f.context.scope(false).unwrap())
        .is_err());
    let receipt = Receipt {
        outcome: Outcome::EmptyClosed {
            etag: "\"empty\"".into(),
            guard_stamp: f.stamp(&turn),
        },
        turn,
    };
    assert!(state::terminal(&head, &f.config, &receipt).is_err());
}

mod recovery;

#[path = "tests/observation.rs"]
mod observation;

#[path = "tests/boxed_journal.rs"]
mod boxed_journal;

mod semantic_observation;
