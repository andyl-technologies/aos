//! Focused original authority, protected artifact, and fixed clock regressions.
//!
//! These invoke the genuine protected capability evaluator and artifact joins.
//! They do not qualify the installed SSH monitor or downstream consume socket.

use super::*;
use crate::publisher_authority::{PublisherAuthorityLimits, PublisherCapabilityRegistry};
use crate::publisher_policy::{
    PreparedPublisherPolicyRevisionV1, PublisherControllerHeadV1, PublisherPolicyLimits,
    PublisherPolicyStore, PublisherRevocationHeadV1,
};
use crate::{JournalLimits, JournalTransaction};
use aos_sandbox_core::{
    CapabilityRecord, DecodeLimits, PrincipalId, ProjectId, RawClockProvenance, ResourceId,
};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

struct ProtectedFixture(std::path::PathBuf);

impl ProtectedFixture {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("aos-original-consume-{}", OperationId::new()));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }

    fn open(&self) -> Journal {
        Journal::open_protected_at_uid(
            &self.0,
            "controller.journal",
            JournalLimits::default(),
            std::fs::metadata(&self.0).unwrap().uid(),
        )
        .unwrap()
        .0
    }
}

impl Drop for ProtectedFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn policy(project: ProjectId, generation: u64, now: i64) -> PreparedPublisherPolicyRevisionV1 {
    // Existing canonical minimal project policy; this fixture exercises the
    // same current policy join as the live public admission validator.
    let encoded = "8b0180808080808082015003030303030303030303030303030303820000f680";
    let bytes: Vec<u8> = encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    PreparedPublisherPolicyRevisionV1::from_canonical_bytes(
        project,
        generation,
        now - 10,
        now + 300,
        &bytes,
        DecodeLimits::default(),
    )
    .unwrap()
}

fn evaluate(
    journal: &mut Journal,
    capability: &CapabilityRecord,
    project: ProjectId,
    holder: PrincipalId,
    key: ChannelBinding,
    selector: &aos_sandbox_core::Selector,
) -> Result<
    CurrentCapabilityDecisionV1,
    crate::cli_model::authorization_adapter::CliAuthorizationAdapterError,
> {
    evaluate_current_protected_capability(
        journal,
        PublisherAuthorityLimits::default(),
        PublisherPolicyLimits::default(),
        capability.id(),
        project,
        holder,
        key,
        &mut ControllerProtectedClockV1::open_fixed().unwrap(),
        ResourceKind::Execution,
        Operation::LifecycleControl,
        selector,
    )
}

#[test]
fn original_attach_grant_current_policy_holder_scope_and_revocation_survive_reopen() {
    let directory = ProtectedFixture::new();
    let mut journal = directory.open();
    let now = ControllerProtectedClockV1::open_fixed()
        .unwrap()
        .sample()
        .unwrap()
        .wall_seconds();
    let seed = crate::publisher_authority::tests::capability(
        CapabilityId::from_bytes([31; 16]),
        now + 300,
    );
    let initial_policy = policy(seed.claims().project, 1, now);
    let mut draft = seed.claims().clone();
    draft.not_before = now - 10;
    draft.policy_digest = initial_policy.descriptor().digest();
    draft.revocation_generation = aos_sandbox_core::Revision::new(1);
    draft.grants = vec![
        aos_sandbox_core::Grant::new(
            aos_sandbox_core::GrantId::from_bytes([45; 16]),
            ResourceKind::Execution,
            aos_sandbox_core::OperationSet::one(Operation::LifecycleControl),
            draft.grants[0].selector().clone(),
            false,
        )
        .unwrap(),
    ];
    let capability = CapabilityRecord::issue(draft).unwrap();
    let claims = capability.claims();
    {
        let mut store =
            PublisherPolicyStore::load(&mut journal, PublisherPolicyLimits::default()).unwrap();
        store
            .advance_controller_from_trusted_controller(
                [32; 16],
                None,
                PublisherControllerHeadV1 {
                    principal: claims.audience,
                    generation: 1,
                },
            )
            .unwrap();
        store
            .advance_revocation_from_trusted_controller(
                [34; 16],
                None,
                PublisherRevocationHeadV1 {
                    scope: claims.revocation_scope,
                    generation: 1,
                },
            )
            .unwrap();
        store
            .publish_policy_from_trusted_controller([35; 16], None, &initial_policy)
            .unwrap();
    }
    PublisherCapabilityRegistry::load(&mut journal, PublisherAuthorityLimits::default())
        .unwrap()
        .install_from_trusted_controller([36; 16], capability.clone())
        .unwrap();
    let selector = claims.grants[0].selector();
    let current = evaluate(
        &mut journal,
        &capability,
        claims.project,
        claims.holder,
        claims.channel_binding,
        selector,
    )
    .unwrap();
    assert_eq!(current.capability(), &capability);
    assert_eq!(current.policy(), &initial_policy);
    assert!(
        evaluate_current_protected_capability(
            &mut journal,
            PublisherAuthorityLimits::default(),
            PublisherPolicyLimits::default(),
            capability.id(),
            claims.project,
            claims.holder,
            claims.channel_binding,
            &mut ControllerProtectedClockV1::open_fixed().unwrap(),
            ResourceKind::Execution,
            Operation::Attach,
            selector
        )
        .is_err()
    );
    let original = current.original_coordinates([37; 32]);
    drop(journal);

    let mut reopened = directory.open();
    let retry = evaluate(
        &mut reopened,
        &capability,
        claims.project,
        claims.holder,
        claims.channel_binding,
        selector,
    )
    .unwrap();
    assert!(crate::attach_decision::same_original_scope(
        &original,
        &retry.original_coordinates([38; 32])
    ));
    assert_eq!(original.session_commitment, [37; 32]);
    assert!(
        evaluate(
            &mut reopened,
            &capability,
            ProjectId::from_bytes([39; 16]),
            claims.holder,
            claims.channel_binding,
            selector
        )
        .is_err()
    );
    assert!(
        evaluate(
            &mut reopened,
            &capability,
            claims.project,
            PrincipalId::from_bytes([39; 16]),
            claims.channel_binding,
            selector
        )
        .is_err()
    );
    assert!(
        evaluate(
            &mut reopened,
            &capability,
            claims.project,
            claims.holder,
            ChannelBinding::new([39; 32]),
            selector
        )
        .is_err()
    );
    assert!(
        evaluate(
            &mut reopened,
            &capability,
            claims.project,
            claims.holder,
            claims.channel_binding,
            &aos_sandbox_core::Selector::Resource {
                resource: ResourceId::from_bytes([39; 16])
            }
        )
        .is_err()
    );
    let mut expired = capability.claims().clone();
    expired.id = CapabilityId::from_bytes([42; 16]);
    expired.expires_at = now - 1;
    let expired = CapabilityRecord::issue(expired).unwrap();
    PublisherCapabilityRegistry::load(&mut reopened, PublisherAuthorityLimits::default())
        .unwrap()
        .install_from_trusted_controller([43; 16], expired.clone())
        .unwrap();
    assert!(
        evaluate(
            &mut reopened,
            &expired,
            claims.project,
            claims.holder,
            claims.channel_binding,
            selector
        )
        .is_err()
    );
    let successor = policy(claims.project, 2, now);
    PublisherPolicyStore::load(&mut reopened, PublisherPolicyLimits::default())
        .unwrap()
        .publish_policy_from_trusted_controller([44; 16], Some(1), &successor)
        .unwrap();
    let changed_policy = evaluate(
        &mut reopened,
        &capability,
        claims.project,
        claims.holder,
        claims.channel_binding,
        selector,
    )
    .unwrap();
    assert!(!crate::attach_decision::same_original_scope(
        &original,
        &changed_policy.original_coordinates([37; 32])
    ));
    {
        let mut store =
            PublisherPolicyStore::load(&mut reopened, PublisherPolicyLimits::default()).unwrap();
        store
            .advance_controller_from_trusted_controller(
                [40; 16],
                Some(1),
                PublisherControllerHeadV1 {
                    principal: claims.audience,
                    generation: 2,
                },
            )
            .unwrap();
    }
    let changed = evaluate(
        &mut reopened,
        &capability,
        claims.project,
        claims.holder,
        claims.channel_binding,
        selector,
    )
    .unwrap();
    assert!(!crate::attach_decision::same_original_scope(
        &original,
        &changed.original_coordinates([37; 32])
    ));
    PublisherPolicyStore::load(&mut reopened, PublisherPolicyLimits::default())
        .unwrap()
        .advance_revocation_from_trusted_controller(
            [41; 16],
            Some(1),
            PublisherRevocationHeadV1 {
                scope: claims.revocation_scope,
                generation: 2,
            },
        )
        .unwrap();
    assert!(
        evaluate(
            &mut reopened,
            &capability,
            claims.project,
            claims.holder,
            claims.channel_binding,
            selector
        )
        .is_err()
    );
}

fn sample(boot: u8, wall: i64, boottime: u64) -> RawPairedClockSample {
    RawPairedClockSample::new_untrusted(
        RawClockProvenance::new_untrusted(*b"aos-cli-clock-v1").unwrap(),
        [boot; 16],
        wall,
        boottime,
    )
    .unwrap()
}

#[test]
fn original_attach_grant_clock_cannot_extend_expiry_or_rebase_after_restart() {
    let original = sample(1, 100, 10_000_000_000);
    let deadline = cut_deadline(original, 130).unwrap();
    assert_eq!(deadline, 39_000_000_000);
    assert!(require_cut_clock(original, sample(1, 128, 38_000_000_000), 130, deadline).is_ok());
    assert!(require_cut_clock(original, sample(1, 128, deadline), 130, deadline).is_err());
    assert!(require_cut_clock(original, sample(1, 130, 40_000_000_000), 130, deadline).is_err());
    assert!(require_cut_clock(original, sample(1, 99, 11_000_000_000), 130, deadline).is_err());
    assert!(require_cut_clock(original, sample(2, 101, 11_000_000_000), 130, deadline).is_err());
    assert!(require_cut_clock(original, sample(1, 110, 11_000_000_000), 130, deadline).is_err());
    assert!(cut_deadline(original, 100).is_err());
    assert!(cut_deadline(original, 101).is_err());
    assert!(cut_deadline(sample(1, 100, u64::MAX), 130).is_err());
}

fn ssh_key(seed: u8) -> ssh_key::PrivateKey {
    ssh_key::PrivateKey::new(
        ssh_key::private::Ed25519Keypair::from_seed(&[seed; 32]).into(),
        "",
    )
    .unwrap()
}

fn execution_projection(
    pending: &crate::public_attach_pending::PublicAttachPendingV1,
    parent: &BrokerAuthorizationPlan,
    operation: OperationId,
    phase: aos_proto::aos::sandbox::v1::ExecutionPhase,
) -> crate::JournalRecord {
    use crate::controller_service::public_projection::{
        PublicProjectionPlanV1, PublicProjectionResourceV1,
    };
    use aos_proto::aos::sandbox::v1::{Command, Duration, Execution, ExecutionIoMode, Timestamp};

    let execution = Execution {
        execution_id: pending.execution_id().to_vec(),
        sandbox_id: parent.assignment().sandbox().as_bytes().to_vec(),
        sandbox_incarnation_id: pending.sandbox_incarnation_id().to_vec(),
        resource_version: vec![75; 32],
        command: Some(Command {
            arguments: vec![b"program".to_vec()],
            execution_timeout: Some(Duration {
                nanoseconds: 1,
                ..Default::default()
            })
            .into(),
            io_mode: ExecutionIoMode::EXECUTION_IO_MODE_STREAM.into(),
            ..Default::default()
        })
        .into(),
        phase: phase.into(),
        audit_id: pending.audit_id().to_vec(),
        desired_generation: 1,
        observation_sequence: 1,
        assignment_epoch: pending.assignment_epoch(),
        last_successful_reconciliation_time: Some(Timestamp {
            seconds: 100,
            ..Default::default()
        })
        .into(),
        ..Default::default()
    };
    let (key, value) = PublicProjectionPlanV1::new(
        ProjectId::from_bytes([2; 16]),
        operation,
        PublicProjectionResourceV1::Execution(execution),
    )
    .unwrap()
    .into_desired_state();
    crate::JournalRecord::put(crate::RecordNamespace::DesiredState, key, value)
}

#[test]
fn original_attach_grant_protected_artifacts_reopen_without_substitution_or_renewal() {
    let directory = ProtectedFixture::new();
    let mut journal = directory.open();
    let (_, prepared) = crate::publication::tests::descriptor_free_activation_fixture(1);
    crate::publication::AuthorityPublicationStore::new(&mut journal)
        .publish(
            &prepared,
            &crate::IdempotencyKey::new("original-consume-publication").unwrap(),
            OperationId::from_bytes([51; 16]),
            [52; 16],
        )
        .unwrap();
    let publication = crate::publication::AuthorityPublicationStore::new(&mut journal)
        .current(prepared.manifest().manifest().sandbox())
        .unwrap()
        .unwrap();
    let parent = publication
        .templates()
        .iter()
        .find(|template| template.audience() == BrokerAudience::Host)
        .unwrap()
        .plan()
        .clone();
    let pending = crate::public_attach_pending::reserve_public_attach_pending_v1(
        &mut journal,
        &crate::IdempotencyKey::new("original-consume-pending").unwrap(),
        [53; 32],
        [54; 16],
        *parent.assignment().incarnation().as_bytes(),
        parent.assignment().epoch().get(),
        [55; 16],
        [56; 16],
        100,
        190,
    )
    .unwrap();
    let signer = ed25519_dalek::SigningKey::from_bytes(&[57; 32]);
    let grant = PublicAttachPendingGrantV1 {
        operation_id: *pending.operation_id().as_bytes(),
        execution_id: pending.execution_id(),
        sandbox_id: *parent.assignment().sandbox().as_bytes(),
        incarnation_id: pending.sandbox_incarnation_id(),
        node_id: *parent.node().as_bytes(),
        assignment_epoch: pending.assignment_epoch(),
        desired_generation: publication.manifest().manifest().desired_generation().get(),
        namespace_generation: publication
            .manifest()
            .manifest()
            .namespace_generation()
            .get(),
        assignment_digest: *parent.assignment().digest().as_bytes(),
        lease_generation: publication.lease_generation(),
        lease_digest: *publication.lease_digest().as_bytes(),
        principal_id: pending.principal_id(),
        audit_id: pending.audit_id(),
        expires_at: pending.expires_at(),
        request_digest: pending.request_digest(),
        pending_digest: pending.record_digest(),
        trust_digest: [58; 32],
        gate_config_digest: [59; 32],
    };
    let original_grant =
        aos_sandbox_core::public_attach_grant::sign_public_attach_pending_grant_v1(&grant, &signer)
            .unwrap();
    let holder = ssh_key(60);
    let mut builder = ssh_key::certificate::Builder::new(
        [61; 32],
        holder.public_key().key_data().clone(),
        100,
        180,
    )
    .unwrap();
    builder
        .cert_type(ssh_key::certificate::CertType::User)
        .unwrap()
        .valid_principal("aos_exec")
        .unwrap();
    let certificate = builder
        .sign(&ssh_key(62))
        .unwrap()
        .to_openssh()
        .unwrap()
        .into_bytes();
    let coordinates = crate::cli_model::provenance::OriginalPublicMutationCoordinatesV2 {
        capability: [63; 16],
        revocation_scope: [64; 16],
        revocation_generation: 1,
        policy_digest: [65; 32],
        policy_generation: 1,
        controller: [66; 16],
        controller_generation: 1,
        capability_not_before: 90,
        capability_expires_at: 200,
        policy_not_before: 80,
        policy_expires_at: 210,
        channel_binding: [67; 32],
        session_commitment: [68; 32],
        authorization_revision: [69; 32],
    };
    // Artifact tests do not construct a current cut. The production entry must
    // independently decode and authorize the original accepted request.
    let checked = crate::attach_decision::encode_original_decision(
        b"original-envelope-artifact-fixture",
        coordinates,
        [[70; 32]; 4],
        PrincipalId::from_bytes(pending.principal_id()),
        ProjectId::from_bytes([2; 16]),
        100,
    )
    .unwrap();
    let issued = crate::attach_decision::bind_issued_decision(
        &checked,
        &certificate,
        [71; 32],
        &original_grant,
    )
    .unwrap();
    journal
        .commit(
            &JournalTransaction::new(
                [72; 16],
                vec![
                    crate::attach_decision::decision_record(pending.operation_id(), issued)
                        .unwrap(),
                ],
            )
            .unwrap(),
        )
        .unwrap();
    crate::attach_decision::retain_original_grant(
        &mut journal,
        pending.record_digest(),
        &original_grant,
    )
    .unwrap();
    let ticket = PublicAttachTicketBindingV2 {
        operation_id: *pending.operation_id().as_bytes(),
        execution_id: pending.execution_id(),
        incarnation_id: pending.sandbox_incarnation_id(),
        principal_id: pending.principal_id(),
        audit_id: pending.audit_id(),
        assignment_epoch: pending.assignment_epoch(),
        valid_after: 100,
        expires_at: 180,
        holder_public_key: holder.public_key().key_data().ed25519().unwrap().0,
        request_digest: pending.request_digest(),
        decision_digest: crate::attach_decision::decision_digest(&journal, pending.operation_id())
            .unwrap(),
        pending_grant: original_grant,
        base_route_digest: [71; 32],
        certificate: certificate.clone(),
    };
    let ticket_bytes = ticket.encode().unwrap();
    crate::attach_decision::retain_original_ticket(
        &mut journal,
        pending.operation_id(),
        &ticket_bytes,
    )
    .unwrap();
    journal
        .commit(
            &JournalTransaction::new(
                [76; 16],
                vec![execution_projection(
                    &pending,
                    &parent,
                    pending.operation_id(),
                    aos_proto::aos::sandbox::v1::ExecutionPhase::EXECUTION_PHASE_RUNNING,
                )],
            )
            .unwrap(),
        )
        .unwrap();
    drop(journal);

    let mut journal = directory.open();
    let original =
        crate::attach_decision::original_decision(&journal, pending.operation_id()).unwrap();
    assert_eq!(
        crate::attach_decision::original_ticket(&journal, pending.operation_id()).unwrap(),
        ticket_bytes
    );
    assert_eq!(
        crate::attach_decision::original_grant(&journal, pending.record_digest()).unwrap(),
        original_grant
    );
    let request_holder = holder.public_key().to_openssh().unwrap().into_bytes();
    let check =
        |ticket: &PublicAttachTicketBindingV2, grant: &PublicAttachPendingGrantV1, trust, now| {
            require_original_ticket(
                &journal,
                pending.operation_id(),
                &original,
                ticket,
                grant,
                &pending,
                &parent,
                &publication,
                &original_grant,
                &certificate,
                &request_holder,
                trust,
                now,
            )
        };
    assert!(check(&ticket, &grant, grant.trust_digest, 150).is_ok());
    let ticket_mutations: [fn(&mut PublicAttachTicketBindingV2); 8] = [
        |ticket: &mut PublicAttachTicketBindingV2| ticket.request_digest = [73; 32],
        |ticket: &mut PublicAttachTicketBindingV2| ticket.decision_digest = [73; 32],
        |ticket: &mut PublicAttachTicketBindingV2| ticket.holder_public_key = [73; 32],
        |ticket: &mut PublicAttachTicketBindingV2| ticket.expires_at += 1,
        |ticket: &mut PublicAttachTicketBindingV2| ticket.assignment_epoch += 1,
        |ticket: &mut PublicAttachTicketBindingV2| ticket.base_route_digest = [73; 32],
        |ticket: &mut PublicAttachTicketBindingV2| ticket.pending_grant[415] ^= 1,
        |ticket: &mut PublicAttachTicketBindingV2| ticket.certificate.push(b' '),
    ];
    for mutate in ticket_mutations {
        let mut substituted = ticket.clone();
        mutate(&mut substituted);
        assert!(check(&substituted, &grant, grant.trust_digest, 150).is_err());
    }
    let grant_mutations: [fn(&mut PublicAttachPendingGrantV1); 6] = [
        |grant: &mut PublicAttachPendingGrantV1| grant.lease_generation += 1,
        |grant: &mut PublicAttachPendingGrantV1| grant.lease_digest = [73; 32],
        |grant: &mut PublicAttachPendingGrantV1| grant.assignment_digest = [73; 32],
        |grant: &mut PublicAttachPendingGrantV1| grant.desired_generation += 1,
        |grant: &mut PublicAttachPendingGrantV1| grant.namespace_generation += 1,
        |grant: &mut PublicAttachPendingGrantV1| grant.expires_at += 1,
    ];
    for mutate in grant_mutations {
        let mut substituted = grant;
        mutate(&mut substituted);
        assert!(check(&ticket, &substituted, grant.trust_digest, 150).is_err());
    }
    assert!(check(&ticket, &grant, [73; 32], 150).is_err());
    assert!(check(&ticket, &grant, grant.trust_digest, 99).is_err());
    assert!(check(&ticket, &grant, grant.trust_digest, 180).is_err());
    assert!(
        crate::attach_decision::original_ticket(&journal, OperationId::from_bytes([74; 16]))
            .is_err()
    );
    assert_eq!(
        crate::attach_decision::original_ticket(&journal, pending.operation_id()).unwrap(),
        ticket_bytes
    );

    // Candidate selection reads real protected projection/publication rows but
    // grants no authority. The owning current-cut entry performs full reauth.
    assert_eq!(
        select_original_candidates(&journal, parent.node(), 1, 150, &signer.verifying_key())
            .unwrap(),
        vec![pending.operation_id()]
    );
    assert!(
        select_original_candidates(
            &journal,
            NodeId::from_bytes([77; 16]),
            1,
            150,
            &signer.verifying_key(),
        )
        .unwrap()
        .is_empty()
    );
    for now in [99, 180, 190] {
        assert!(
            select_original_candidates(&journal, parent.node(), 1, now, &signer.verifying_key())
                .unwrap()
                .is_empty()
        );
    }
    for (transaction, operation, phase) in [
        (
            [78; 16],
            OperationId::from_bytes([79; 16]),
            aos_proto::aos::sandbox::v1::ExecutionPhase::EXECUTION_PHASE_RUNNING,
        ),
        (
            [80; 16],
            pending.operation_id(),
            aos_proto::aos::sandbox::v1::ExecutionPhase::EXECUTION_PHASE_REQUESTED,
        ),
    ] {
        journal
            .commit(
                &JournalTransaction::new(
                    transaction,
                    vec![execution_projection(&pending, &parent, operation, phase)],
                )
                .unwrap(),
            )
            .unwrap();
        drop(journal);
        journal = directory.open();
        assert!(
            select_original_candidates(&journal, parent.node(), 1, 150, &signer.verifying_key())
                .unwrap()
                .is_empty()
        );
    }

    journal
        .commit(
            &JournalTransaction::new(
                [85; 16],
                vec![execution_projection(
                    &pending,
                    &parent,
                    pending.operation_id(),
                    aos_proto::aos::sandbox::v1::ExecutionPhase::EXECUTION_PHASE_RUNNING,
                )],
            )
            .unwrap(),
        )
        .unwrap();
    assert_eq!(
        select_original_candidates(&journal, parent.node(), 1, 150, &signer.verifying_key())
            .unwrap(),
        vec![pending.operation_id()]
    );
    let mut unrelated_key = b"original-attach-ticket-v2/".to_vec();
    unrelated_key.extend_from_slice(&[u8::MAX; 16]);
    journal
        .commit(
            &JournalTransaction::new(
                [86; 16],
                vec![crate::JournalRecord::put(
                    crate::RecordNamespace::PublicAttachRoute,
                    unrelated_key,
                    b"malformed-after-bounded-valid-candidate".to_vec(),
                )],
            )
            .unwrap(),
        )
        .unwrap();
    drop(journal);
    let journal = directory.open();
    assert!(
        select_original_candidates(&journal, parent.node(), 1, 150, &signer.verifying_key())
            .is_err()
    );
}

#[test]
fn original_attach_candidates_reject_unbounded_or_malformed_protected_input() {
    let directory = ProtectedFixture::new();
    let mut journal = directory.open();
    let node = NodeId::from_bytes([81; 16]);
    let verifier = ed25519_dalek::SigningKey::from_bytes(&[82; 32]).verifying_key();
    assert!(
        select_original_candidates(&journal, node, 1, 100, &verifier)
            .unwrap()
            .is_empty()
    );
    for maximum in [0, 33, usize::MAX] {
        assert!(select_original_candidates(&journal, node, maximum, 100, &verifier).is_err());
    }
    assert!(
        select_original_candidates(&journal, NodeId::from_bytes([0; 16]), 1, 100, &verifier)
            .is_err()
    );
    assert!(select_original_candidates(&journal, node, 1, -1, &verifier).is_err());

    let mut key = b"original-attach-ticket-v2/".to_vec();
    key.extend_from_slice(&[83; 16]);
    journal
        .commit(
            &JournalTransaction::new(
                [84; 16],
                vec![crate::JournalRecord::put(
                    crate::RecordNamespace::PublicAttachRoute,
                    key,
                    b"malformed-unrelated-original-ticket".to_vec(),
                )],
            )
            .unwrap(),
        )
        .unwrap();
    drop(journal);
    let journal = directory.open();
    assert!(select_original_candidates(&journal, node, 1, 100, &verifier).is_err());
}
