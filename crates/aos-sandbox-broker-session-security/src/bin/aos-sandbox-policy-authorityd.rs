//! Admits externally signed deployment policy inputs under root-owned custody.
//!
//! This service commits the monotonic deployment input head and serves an
//! authenticated signed-head receipt to the node controller. Its version-4
//! exchange can retain a closed AOSPCB02 root CAS and handoff epoch. It cannot
//! admit the project source against the controller-owned publisher journal,
//! authorize compiler publication, or authorize Create effects. A separate
//! version-5 exchange spends a root challenge and verifies a Cache-only signed
//! readback. Version 6 stages a distinct challenge before Controller takes
//! owner locks, then records the exact V2 packet with Root acquired last.
//! Neither exchange promotes the packet into Q04 authority.
//! Root-only recovery modes inspect or release an abandoned version-4 hold.
//! A separate credential-independent V7 listener answers historical Cache
//! packet recovery only for the authenticated Controller peer.
//! `AOSPHQ4V` performs an inert staged Root-last comparison. Bare `AOSPHQ04`
//! remains denied before Root custody. A held-cut marker selects a separate
//! staged `AOSPHQ04` exchange: Source-only and Cache-only signers attest one
//! challenge, then Root durably commits the exact binding/head/held decision.
//! `AOSPHQ4F` uses the same flight but returns only an inert preview. Neither
//! exchange opens public Create or releases custody for downstream effects.
//! `AOSPHQ5F` separately spends a fresh Source challenge under Root-last
//! custody and checks the Source V2 signed journal/lock identities. It is
//! preview-only and cannot enter the V4 qualified-CAS path.
//! `--show-controller-hold` inspects the protected Controller record;
//! `--release-controller-hold` checks exact root custody under the fixed
//! Controller-then-root lock order before unfreezing the Controller journal.
//! `--release-source-domain-hold` retains Controller and source-domain writers
//! in that order before exact root cold readback; it must precede Controller
//! release when both journals are held.

use std::{
    error::Error,
    fs::File,
    io::{self, Read, Write},
    os::unix::{fs::FileTypeExt as _, net::UnixListener},
    path::Path,
    process::ExitCode,
    time::Duration,
    time::{SystemTime, UNIX_EPOCH},
};

use aos_sandbox::cache_residency::{
    CLOSED_CACHE_OWNER_READBACK_BYTES_V2, PinnedCacheOwnerReadbackSignerV1,
};
use aos_sandbox::journal::{ProtectedJournalNamesV1, SourceDomainPolicyHoldV1};
use aos_sandbox::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1;
use aos_sandbox::policy_compiler::{
    CLOSED_POLICY_BINDING_BYTES_V2, CacheSignerRootChallengeStatusV2,
    CacheSignerRootSettlementStateV2, ClosedCacheReadbackRootChallengeV1,
    ClosedPolicyBindingDecisionV2, ClosedPolicyRootCasBaseV2, ClosedSourceTerminalClaimV1,
    PinnedSourceHoldReadbackSignerV1, PolicyDeploymentInputsV1, StagedClosedPolicyRootBaseV2,
    abandon_fixed_cache_signer_challenge_v2, acknowledge_fixed_closed_root_effect_v1,
    admit_fixed_cache_readback_pin_v1, admit_fixed_controller_hold_pin_v1,
    admit_fixed_policy_deployment_head_v1, admit_fixed_policy_signer_pins_v1,
    admit_fixed_source_hold_pin_v1, compact_fixed_cache_signer_root_journal_v2,
    decode_policy_deployment_sources_v1, read_fixed_cache_signer_challenge_v2,
    read_fixed_inert_closed_policy_binding_hold_v1, read_fixed_policy_cache_hold_v1,
    record_fixed_cache_signer_root_settlement_v2, recover_fixed_cache_signer_abandonment_v2,
    recover_fixed_cache_signer_root_history_v2, recover_fixed_cache_signer_root_settlement_v2,
    recover_fixed_closed_policy_binding_decision_v2, recover_fixed_closed_root_effect_ack_v1,
    recover_fixed_committed_source_held_binding_v2, release_fixed_closed_policy_controller_hold_v1,
    release_fixed_closed_policy_source_domain_hold_v1,
    release_fixed_inert_closed_policy_binding_hold_v1,
    require_no_fixed_closed_policy_binding_hold_v1, stage_fixed_cache_signer_challenge_v2,
    staged_closed_policy_signer_challenge_v2, verify_fixed_policy_cache_owner_readback_v2,
    verify_policy_deployment_head_v1, verify_signed_project_policy_source_v1,
    verify_signed_project_policy_source_v2, with_fixed_closed_cache_readback_session_v1,
    with_fixed_current_policy_head_lease_v1, with_fixed_explicit_closed_policy_binding_session_v2,
};
use aos_sandbox::{Journal, controller_service::journal::production_journal_limits};
use aos_sandbox_broker_session_security::cache_signer_exchange::{
    begin_root_cache_signer_exchange_v2, begin_root_q04_cache_signer_exchange_v3,
};
use aos_sandbox_broker_session_security::policy_authority_client::{
    POLICY_AUTHORITY_SOCKET_PATH_V2, POLICY_BINDING_ACK_MAGIC_V4, POLICY_BINDING_BASE_MAGIC_V4,
    POLICY_BINDING_COMMITTED_MAGIC_V4, POLICY_BINDING_COMPLETE_MAGIC_V4,
    POLICY_BINDING_FLIGHT_CHALLENGE_MAGIC_V4, POLICY_BINDING_FLIGHT_QUERY_MAGIC_V4,
    POLICY_BINDING_FLIGHT_REPLY_MAGIC_V4, POLICY_BINDING_FLIGHT_SUBMIT_MAGIC_V4,
    POLICY_BINDING_HELD_MARKER_V4, POLICY_BINDING_PREVIEW_QUERY_MAGIC_V4,
    POLICY_BINDING_PREVIEW_REPLY_MAGIC_V4, POLICY_BINDING_QUERY_MAGIC_V4,
    POLICY_BINDING_RECEIPT_MAGIC_V4, POLICY_BINDING_REPLAY_QUERY_MAGIC_V5,
    POLICY_BINDING_REPLAY_REPLY_MAGIC_V5, POLICY_BINDING_SOURCE_FLIGHT_CHALLENGE_MAGIC_V5,
    POLICY_BINDING_SOURCE_FLIGHT_CHALLENGE_MAGIC_V6,
    POLICY_BINDING_SOURCE_FLIGHT_CHALLENGE_MAGIC_V7,
    POLICY_BINDING_SOURCE_FLIGHT_CHALLENGE_MAGIC_V8, POLICY_BINDING_SOURCE_FLIGHT_DONE_MAGIC_V6,
    POLICY_BINDING_SOURCE_FLIGHT_DONE_MAGIC_V7, POLICY_BINDING_SOURCE_FLIGHT_DONE_MAGIC_V8,
    POLICY_BINDING_SOURCE_FLIGHT_QUERY_MAGIC_V5, POLICY_BINDING_SOURCE_FLIGHT_QUERY_MAGIC_V6,
    POLICY_BINDING_SOURCE_FLIGHT_QUERY_MAGIC_V7, POLICY_BINDING_SOURCE_FLIGHT_QUERY_MAGIC_V8,
    POLICY_BINDING_SOURCE_FLIGHT_REPLAY_QUERY_MAGIC_V7,
    POLICY_BINDING_SOURCE_FLIGHT_REPLAY_QUERY_MAGIC_V8,
    POLICY_BINDING_SOURCE_FLIGHT_REPLAY_REPLY_MAGIC_V7,
    POLICY_BINDING_SOURCE_FLIGHT_REPLAY_REPLY_MAGIC_V8,
    POLICY_BINDING_SOURCE_FLIGHT_REPLY_MAGIC_V5, POLICY_BINDING_SOURCE_FLIGHT_REPLY_MAGIC_V6,
    POLICY_BINDING_SOURCE_FLIGHT_REPLY_MAGIC_V7, POLICY_BINDING_SOURCE_FLIGHT_REPLY_MAGIC_V8,
    POLICY_BINDING_SOURCE_FLIGHT_SUBMIT_MAGIC_V5, POLICY_BINDING_SOURCE_FLIGHT_SUBMIT_MAGIC_V6,
    POLICY_BINDING_SOURCE_FLIGHT_SUBMIT_MAGIC_V7, POLICY_BINDING_SOURCE_FLIGHT_SUBMIT_MAGIC_V8,
    POLICY_BINDING_SOURCE_FLIGHT_TERMINAL_MAGIC_V6, POLICY_BINDING_SOURCE_FLIGHT_TERMINAL_MAGIC_V7,
    POLICY_BINDING_SOURCE_FLIGHT_TERMINAL_MAGIC_V8, POLICY_BINDING_STAGE_QUERY_MAGIC_V4,
    POLICY_BINDING_STAGE_REPLY_MAGIC_V4, POLICY_BINDING_SUBMIT_MAGIC_V4,
    POLICY_BINDING_TERMINAL_ACK_MAGIC_V4, POLICY_HEAD_LEASE_ACK_MAGIC_V3,
    POLICY_HEAD_LEASE_COMPLETE_MAGIC_V3, POLICY_HEAD_LEASE_QUERY_MAGIC_V3,
    POLICY_HEAD_QUERY_MAGIC_V2, POLICY_HEAD_RECEIPT_MAGIC_V2,
};
use aos_sandbox_broker_session_security::policy_cache_readback_client::{
    CLOSED_CACHE_READBACK_SUBMIT_FRAME_BYTES_V5, CLOSED_CACHE_SIGNER_RECOVERY_FRAME_BYTES_V7,
    CLOSED_CACHE_SIGNER_SUBMIT_FRAME_BYTES_V6, CacheSignerRootRecoveryV7,
    POLICY_CACHE_READBACK_CHALLENGE_MAGIC_V5, POLICY_CACHE_READBACK_OBSERVATION_MAGIC_V5,
    POLICY_CACHE_READBACK_QUERY_MAGIC_V5, POLICY_CACHE_READBACK_SUBMIT_MAGIC_V5,
    POLICY_CACHE_SIGNER_CHALLENGE_MAGIC_V6, POLICY_CACHE_SIGNER_QUERY_MAGIC_V6,
    POLICY_CACHE_SIGNER_RECOVERY_QUERY_MAGIC_V7, POLICY_CACHE_SIGNER_RECOVERY_SOCKET_PATH_V7,
    POLICY_CACHE_SIGNER_SETTLED_MAGIC_V6, POLICY_CACHE_SIGNER_SUBMIT_MAGIC_V6,
    decode_cache_signer_recovery_submission_v7, encode_cache_signer_recovery_observation_v7,
};
use aos_sandbox_broker_session_security::policy_root_ack_client::{
    ROOT_EFFECT_ACK_CHALLENGE_FRAME_BYTES_V1, ROOT_EFFECT_ACK_CHALLENGE_MAGIC_V1,
    ROOT_EFFECT_ACK_QUERY_MAGIC_V1, ROOT_EFFECT_ACK_REPLAY_QUERY_MAGIC_V1,
    ROOT_EFFECT_ACK_SUBMIT_FRAME_BYTES_V1, ROOT_EFFECT_ACK_SUBMIT_MAGIC_V1,
    encode_root_effect_ack_reply_v1,
};
use aos_sandbox_broker_session_security::policy_signer_credential::{
    PinnedPolicySignerV1, PolicySignerRoleV1,
};
use aos_sandbox_broker_session_security::source_signer_exchange::{
    request_root_source_signer_readback_with_names_v2, request_root_staged_q04_source_readback_v2,
};
use aos_sandbox_core::{ObjectDigest, OperationId, SandboxId};
use ed25519_dalek::VerifyingKey;
use sha2::{Digest as _, Sha256};

const CREDENTIAL_ROOT: &str = "/run/credentials/aos-sandbox-policy-authorityd.service";
const CONTROLLER_STATE_DIRECTORY: &str = "/var/lib/aos/sandboxd";
const CONTROLLER_JOURNAL: &str = "controller.journal";
const SOURCE_DOMAIN_DIRECTORY: &str = "/var/lib/aos/sandbox/source-domains";
const SOURCE_DOMAIN_JOURNAL: &str = "source-domains-v1.journal";
const REQUEST_BYTES: usize = 32;
const MAXIMUM_RECEIPT_BYTES: usize = 224 + 4 * (4 + 64 * 1024) + 312 + 4 + 3 * 1024 + 24;
const EXPLICIT_PROJECT_PACKET_BYTES: usize = 328;
const LEASE_ACK_TIMEOUT: Duration = Duration::from_secs(30);
const CLOSED_BINDING_SUBMISSION_BYTES: usize = 8 + 16 + 4 + CLOSED_POLICY_BINDING_BYTES_V2;
const CLOSED_BINDING_ACK_BYTES: usize = 8 + 16 + 32 + 8;
const CLOSED_BINDING_REPLAY_CLAIM_BYTES: usize = 32 + 8;
const CLOSED_BINDING_PREVIEW_CLAIM_BYTES: usize = 96 + CLOSED_POLICY_BINDING_BYTES_V2;
const CLOSED_BINDING_FLIGHT_HOLD_BYTES: usize = 16 + 16 + 32 + 32 + 32 + 8;
const CLOSED_BINDING_FLIGHT_SUBMIT_BYTES: usize = 8 + 16 + CLOSED_CACHE_OWNER_READBACK_BYTES_V2;
const SOURCE_FLIGHT_SUBMIT_BYTES_V5: usize = CLOSED_BINDING_FLIGHT_SUBMIT_BYTES + 48;
const CACHE_SIGNER_RPC_TIMEOUT: Duration = Duration::from_secs(75);

#[derive(Clone, Copy)]
enum HeadRequestMode {
    Query,
    Lease,
    ClosedBinding,
    QualifiedClosedBinding,
    ClosedBindingReplay,
    RootEffectAck,
    RootEffectAckReplay,
    ClosedBindingStage,
    ClosedBindingPreview,
    ClosedBindingSignerFlight,
    ClosedBindingSourceWriterFlight,
    ClosedBindingSourceWriterHeldFlight,
    ClosedBindingSourceWriterSignedFlight,
    ClosedBindingSourceWriterCasFlight,
    ClosedBindingSourceTerminalReplay,
    ClosedBindingSourceCasReplay,
    ClosedCacheReadback,
    StagedCacheSigner,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("aos-sandbox-policy-authorityd: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    if rustix::process::geteuid().as_raw() != 0 || rustix::process::getuid().as_raw() != 0 {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "root required").into());
    }

    let mut arguments = std::env::args();
    let _program = arguments.next();
    let first = arguments
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "controller UID required"))?;
    if first == "--serve-cache-signer-recovery" {
        let controller_uid: u32 = arguments
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "controller UID required"))?
            .parse()?;
        let controller_gid: u32 = arguments
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "controller GID required"))?
            .parse()?;
        if controller_uid == 0 || controller_gid == 0 || arguments.next().is_some() {
            return Err(
                io::Error::new(io::ErrorKind::InvalidInput, "invalid recovery peer").into(),
            );
        }
        return serve_cache_signer_recovery_only(controller_uid, controller_gid);
    }
    if first == "--compact-policy-authority-journal" {
        if arguments.next().is_some() {
            return Err(
                io::Error::new(io::ErrorKind::InvalidInput, "extra recovery argument").into(),
            );
        }
        compact_fixed_cache_signer_root_journal_v2()?;
        return Ok(());
    }
    if first == "--show-cache-signer-challenge" {
        if arguments.next().is_some() {
            return Err(
                io::Error::new(io::ErrorKind::InvalidInput, "extra recovery argument").into(),
            );
        }
        match read_fixed_cache_signer_challenge_v2()? {
            Some(readback) => {
                let challenge = readback.challenge();
                let status = match readback.status() {
                    CacheSignerRootChallengeStatusV2::Pending => "pending".to_owned(),
                    CacheSignerRootChallengeStatusV2::Abandoned => "abandoned".to_owned(),
                    CacheSignerRootChallengeStatusV2::Recorded(digest) => {
                        format!("recorded {}", binding_head_hex(digest))
                    }
                };
                println!(
                    "{} {} {} {}",
                    challenge.epoch(),
                    nonce_hex(challenge.readback().nonce()),
                    binding_head_hex(challenge.readback().cut()),
                    status
                );
            }
            None => println!("none"),
        }
        return Ok(());
    }
    if first == "--abandon-cache-signer-challenge" {
        let epoch: u64 = arguments
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "epoch required"))?
            .parse()?;
        let nonce = parse_cache_nonce(
            &arguments
                .next()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "nonce required"))?,
        )?;
        let cut =
            parse_binding_head(&arguments.next().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "root cut required")
            })?)?;
        if epoch == 0 || arguments.next().is_some() {
            return Err(
                io::Error::new(io::ErrorKind::InvalidInput, "invalid recovery identity").into(),
            );
        }
        let readback = read_fixed_cache_signer_challenge_v2()?.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "Cache signer challenge absent")
        })?;
        let challenge = readback.challenge();
        if challenge.epoch() != epoch
            || challenge.readback().nonce() != nonce
            || challenge.readback().cut() != cut
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Cache signer challenge mismatch",
            )
            .into());
        }
        match readback.status() {
            CacheSignerRootChallengeStatusV2::Pending => {
                if let Err(error) = abandon_fixed_cache_signer_challenge_v2(challenge) {
                    if !recover_fixed_cache_signer_abandonment_v2(challenge)? {
                        return Err(error.into());
                    }
                }
            }
            CacheSignerRootChallengeStatusV2::Abandoned => {}
            CacheSignerRootChallengeStatusV2::Recorded(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Cache signer challenge already recorded",
                )
                .into());
            }
        }
        return Ok(());
    }
    if first == "--show-inert-hold" {
        if arguments.next().is_some() {
            return Err(
                io::Error::new(io::ErrorKind::InvalidInput, "extra recovery argument").into(),
            );
        }
        match read_fixed_inert_closed_policy_binding_hold_v1()? {
            Some(held) => println!(
                "{} {}",
                binding_head_hex(held.binding()),
                held.handoff_epoch()
            ),
            None => println!("none"),
        }
        return Ok(());
    }
    if first == "--release-inert-hold" {
        let binding = parse_binding_head(&arguments.next().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "binding head required")
        })?)?;
        let epoch: u64 = arguments
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "epoch required"))?
            .parse()?;
        if arguments.next().is_some() {
            return Err(
                io::Error::new(io::ErrorKind::InvalidInput, "extra recovery argument").into(),
            );
        }
        // Q04 cannot dispatch an effect. An operator can retire only the
        // exact abandoned root hold after reviewing the protected binding.
        release_fixed_inert_closed_policy_binding_hold_v1(binding, epoch)?;
        return Ok(());
    }
    if first == "--show-controller-hold" {
        let controller_uid: u32 = arguments
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "controller UID required"))?
            .parse()?;
        if arguments.next().is_some() {
            return Err(
                io::Error::new(io::ErrorKind::InvalidInput, "extra recovery argument").into(),
            );
        }
        let controller = open_controller_recovery_journal(controller_uid)?;
        match controller.controller_policy_hold_v1()? {
            Some(hold) => println!(
                "{} {} {}",
                if hold.is_held() { "held" } else { "released" },
                binding_head_hex(hold.binding()),
                hold.epoch()
            ),
            None => println!("none"),
        }
        return Ok(());
    }
    if first == "--show-source-domain-hold" {
        let controller_uid: u32 = arguments
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "controller UID required"))?
            .parse()?;
        if controller_uid == 0 || arguments.next().is_some() {
            return Err(
                io::Error::new(io::ErrorKind::InvalidInput, "invalid recovery identity").into(),
            );
        }
        let _controller = open_controller_recovery_journal(controller_uid)?;
        let source_domains = open_source_domain_recovery_owner(controller_uid)?;
        match source_domains.closed_policy_source_hold_v1()? {
            Some(hold) => println!(
                "{} {} {}",
                if hold.is_held() { "held" } else { "released" },
                binding_head_hex(hold.binding()),
                hold.epoch()
            ),
            None => println!("none"),
        }
        return Ok(());
    }
    if first == "--release-source-domain-hold" {
        let controller_uid: u32 = arguments
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "controller UID required"))?
            .parse()?;
        let binding = parse_binding_head(&arguments.next().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "binding head required")
        })?)?;
        let epoch: u64 = arguments
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "epoch required"))?
            .parse()?;
        if controller_uid == 0 || epoch == 0 || arguments.next().is_some() {
            return Err(
                io::Error::new(io::ErrorKind::InvalidInput, "invalid recovery identity").into(),
            );
        }
        let mut controller = open_controller_recovery_journal(controller_uid)?;
        let mut source_domains = open_source_domain_recovery_owner(controller_uid)?;
        let held = source_domains
            .closed_policy_source_hold_v1()?
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "source-domain hold absent")
            })?;
        if !held.is_held() || held.binding() != binding || held.epoch() != epoch {
            return Err(
                io::Error::new(io::ErrorKind::InvalidData, "source-domain hold mismatch").into(),
            );
        }
        release_fixed_closed_policy_source_domain_hold_v1(
            &mut controller,
            &mut source_domains,
            held,
        )?;
        return Ok(());
    }
    if first == "--release-controller-hold" {
        let controller_uid: u32 = arguments
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "controller UID required"))?
            .parse()?;
        let binding = parse_binding_head(&arguments.next().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "binding head required")
        })?)?;
        let epoch: u64 = arguments
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "epoch required"))?
            .parse()?;
        if epoch == 0 || arguments.next().is_some() {
            return Err(
                io::Error::new(io::ErrorKind::InvalidInput, "invalid recovery identity").into(),
            );
        }
        let mut controller = open_controller_recovery_journal(controller_uid)?;
        let mut source_domains = open_source_domain_recovery_owner(controller_uid)?;
        let held = controller
            .controller_policy_hold_v1()?
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Controller hold absent"))?;
        if !held.is_held() || held.binding() != binding || held.epoch() != epoch {
            return Err(
                io::Error::new(io::ErrorKind::InvalidData, "Controller hold mismatch").into(),
            );
        }
        // Root readback occurs only after the Controller lock is retained.
        release_fixed_closed_policy_controller_hold_v1(&mut controller, &mut source_domains, held)?;
        return Ok(());
    }
    let controller_uid: u32 = first.parse()?;
    let controller_gid: u32 = arguments
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "controller GID required"))?
        .parse()?;
    let cache_signer_uid: u32 = arguments
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Cache signer UID required"))?
        .parse()?;
    let source_signer_uid: u32 = arguments
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Source signer UID required"))?
        .parse()?;
    if controller_uid == 0 || controller_gid == 0 || arguments.next().is_some() {
        return Err(
            io::Error::new(io::ErrorKind::InvalidInput, "invalid controller identity").into(),
        );
    }

    // An unresolved CAS never reaches credential admission. Its isolated
    // service admits only historical replay and the qualified, nonauthorizing
    // Controller ACK exchange; Root validates the pinned signer before writing.
    if read_fixed_inert_closed_policy_binding_hold_v1()?.is_some() {
        return serve_held_binding_recovery(controller_uid, controller_gid);
    }

    let root = Path::new(CREDENTIAL_ROOT);
    let key_bytes = read_bounded(&root.join("deployment-public-key"), 80)?;
    let deployment_signer =
        PinnedPolicySignerV1::decode(PolicySignerRoleV1::Deployment, &key_bytes)?;
    let packet = read_bounded(&root.join("deployment-head.packet"), 224)?;
    let node = read_bounded(&root.join("node-policy.json"), 64 * 1024)?;
    let site = read_bounded(&root.join("site-policy.json"), 64 * 1024)?;
    let backend = read_bounded(&root.join("backend-capabilities.json"), 64 * 1024)?;
    let catalogs = read_bounded(&root.join("catalogs.json"), 64 * 1024)?;
    let project_key_bytes = read_bounded(&root.join("project-public-key"), 80)?;
    let project_signer =
        PinnedPolicySignerV1::decode(PolicySignerRoleV1::Project, &project_key_bytes)?;
    let legacy_project =
        read_optional_project(root, "project-head.packet", 312, "project-layer.json")?;
    let explicit_project = read_optional_explicit_project(root)?;
    require_single_project_source(legacy_project.is_some(), explicit_project.is_some())?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
    let now_unix_seconds = i64::try_from(now.as_secs())?;

    let inputs = PolicyDeploymentInputsV1 {
        node: &node,
        site: &site,
        backend: &backend,
        catalogs: &catalogs,
    };
    let deployment = verify_policy_deployment_head_v1(
        &packet,
        &inputs,
        deployment_signer.verifying_key(),
        now_unix_seconds,
    )?;
    let _typed_sources = decode_policy_deployment_sources_v1(&inputs, deployment)?;
    if let Some((project_packet, project_input)) = legacy_project.as_ref() {
        let project = verify_signed_project_policy_source_v1(
            project_packet,
            project_input,
            project_signer.verifying_key(),
            now_unix_seconds,
        )?;
        if project.head().prerequisite_claims()[1] != deployment.packet_digest() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "project deployment head mismatch",
            )
            .into());
        }
    }
    if let Some((project_packet_v2, project_input_v2)) = explicit_project.as_ref() {
        let verified = verify_signed_project_policy_source_v2(
            project_packet_v2,
            project_input_v2,
            project_signer.verifying_key(),
            now_unix_seconds,
        )?;
        if verified.head().prerequisite_claims()[1] != deployment.packet_digest()
            || verified.head().deployment_signer_generation() != deployment_signer.generation()
            || verified.head().project_signer_generation() != project_signer.generation()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "explicit project source does not match root signer pins or deployment head",
            )
            .into());
        }
    }
    admit_fixed_policy_signer_pins_v1(
        deployment_signer.generation(),
        deployment_signer.verifying_key(),
        project_signer.generation(),
        project_signer.verifying_key(),
    )?;
    admit_fixed_policy_deployment_head_v1(
        &packet,
        &inputs,
        deployment_signer.verifying_key(),
        now_unix_seconds,
    )?;
    let cache_pin = read_optional_cache_pin(root)?;
    admit_fixed_cache_readback_pin_v1(
        cache_pin.as_deref(),
        deployment_signer.generation(),
        deployment_signer.verifying_key(),
        project_signer.generation(),
        project_signer.verifying_key(),
    )?;
    let controller_hold_pin = read_optional_pin(root, "controller-hold-public-key")?;
    admit_fixed_controller_hold_pin_v1(
        controller_hold_pin.as_deref(),
        deployment_signer.generation(),
        deployment_signer.verifying_key(),
        project_signer.generation(),
        project_signer.verifying_key(),
    )?;
    let source_hold_pin = read_optional_pin(root, "source-hold-public-key")?;
    admit_fixed_source_hold_pin_v1(
        source_hold_pin.as_deref(),
        deployment_signer.generation(),
        deployment_signer.verifying_key(),
        project_signer.generation(),
        project_signer.verifying_key(),
    )?;

    let listener = bind_policy_socket(Path::new(POLICY_AUTHORITY_SOCKET_PATH_V2))?;

    for accepted in listener.incoming() {
        let mut stream = match accepted {
            Ok(stream) => stream,
            Err(error) => return Err(error.into()),
        };
        if let Err(error) = serve_current_head(
            &mut stream,
            controller_uid,
            controller_gid,
            cache_signer_uid,
            source_signer_uid,
            &packet,
            &inputs,
            deployment_signer.verifying_key(),
            deployment_signer.generation(),
            legacy_project
                .as_ref()
                .map(|(packet, input)| (packet.as_slice(), input.as_slice())),
            explicit_project
                .as_ref()
                .map(|(packet, input)| (packet.as_slice(), input.as_slice())),
            project_signer.verifying_key(),
            project_signer.generation(),
            cache_pin.as_deref(),
            source_hold_pin.as_deref(),
            controller_hold_pin.as_deref(),
        ) {
            eprintln!("aos-sandbox-policy-authorityd: rejected head query: {error}");
        }
    }
    Err(io::Error::new(io::ErrorKind::BrokenPipe, "authority listener ended").into())
}

fn serve_held_binding_recovery(
    controller_uid: u32,
    controller_gid: u32,
) -> Result<(), Box<dyn Error>> {
    let listener = bind_policy_socket(Path::new(POLICY_AUTHORITY_SOCKET_PATH_V2))?;
    for accepted in listener.incoming() {
        let mut stream = accepted?;
        if let Err(error) = serve_held_binding_request(&mut stream, controller_uid, controller_gid)
        {
            eprintln!("aos-sandbox-policy-authorityd: rejected held Q04 recovery: {error}");
        }
    }
    Err(io::Error::new(io::ErrorKind::BrokenPipe, "authority listener ended").into())
}

fn serve_held_binding_request(
    stream: &mut std::os::unix::net::UnixStream,
    controller_uid: u32,
    controller_gid: u32,
) -> Result<(), Box<dyn Error>> {
    require_controller_peer(stream, controller_uid, controller_gid)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let (request, mode) = read_head_request(stream, || {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "Root hold unresolved").into())
    })?;
    if !matches!(
        mode,
        HeadRequestMode::ClosedBindingReplay
            | HeadRequestMode::RootEffectAck
            | HeadRequestMode::RootEffectAckReplay
            | HeadRequestMode::ClosedBindingSourceCasReplay
    ) {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "replay only").into());
    }
    match mode {
        HeadRequestMode::ClosedBindingReplay => {
            serve_closed_binding_replay(stream, &request[8..24])
        }
        HeadRequestMode::RootEffectAck => {
            serve_root_effect_ack(stream, &request[8..24], controller_uid)
        }
        HeadRequestMode::RootEffectAckReplay => {
            serve_root_effect_ack_replay(stream, &request[8..24])
        }
        HeadRequestMode::ClosedBindingSourceCasReplay => serve_closed_source_cas_replay_v8(
            stream,
            &request[8..24],
            controller_uid,
            controller_gid,
        ),
        _ => Err(io::Error::new(io::ErrorKind::PermissionDenied, "replay only").into()),
    }
}

fn bind_policy_socket(path: &Path) -> io::Result<UnixListener> {
    match path.symlink_metadata() {
        Ok(metadata) => {
            if !metadata.file_type().is_socket() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "unsafe authority socket path",
                ));
            }
            std::fs::remove_file(path)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    UnixListener::bind(path)
}

fn serve_cache_signer_recovery_only(
    controller_uid: u32,
    controller_gid: u32,
) -> Result<(), Box<dyn Error>> {
    let listener = bind_policy_socket(Path::new(POLICY_CACHE_SIGNER_RECOVERY_SOCKET_PATH_V7))?;
    for accepted in listener.incoming() {
        let mut stream = accepted?;
        if let Err(error) =
            serve_cache_signer_recovery_request(&mut stream, controller_uid, controller_gid)
        {
            eprintln!("aos-sandbox-policy-authorityd: rejected Cache recovery query: {error}");
        }
    }
    Err(io::Error::new(io::ErrorKind::BrokenPipe, "recovery listener ended").into())
}

fn serve_cache_signer_recovery_request(
    stream: &mut std::os::unix::net::UnixStream,
    controller_uid: u32,
    controller_gid: u32,
) -> Result<(), Box<dyn Error>> {
    let peer = rustix::net::sockopt::socket_peercred(&*stream)?;
    if peer.uid.as_raw() != controller_uid || peer.gid.as_raw() != controller_gid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unexpected controller peer",
        )
        .into());
    }
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    let request = read_cache_signer_recovery_header(stream)?;
    let client_nonce: [u8; 16] = request[8..24].try_into()?;
    serve_cache_signer_recovery(stream, client_nonce)
}

fn read_cache_signer_recovery_header(
    stream: &mut std::os::unix::net::UnixStream,
) -> io::Result<[u8; REQUEST_BYTES]> {
    let mut request = [0_u8; REQUEST_BYTES];
    stream.read_exact(&mut request)?;
    if &request[..8] != POLICY_CACHE_SIGNER_RECOVERY_QUERY_MAGIC_V7
        || request[8..24] == [0; 16]
        || request[24..] != [0; 8]
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid Cache recovery request",
        ));
    }
    Ok(request)
}

fn open_controller_recovery_journal(controller_uid: u32) -> Result<Journal, Box<dyn Error>> {
    if controller_uid == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid controller UID").into());
    }
    let controller_path = Path::new(CONTROLLER_STATE_DIRECTORY).join(CONTROLLER_JOURNAL);
    if !controller_path.exists() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "Controller journal absent").into());
    }
    let (controller, _) = Journal::open_protected_at_for_uid(
        CONTROLLER_STATE_DIRECTORY,
        CONTROLLER_JOURNAL,
        production_journal_limits(),
        controller_uid,
    )?;
    Ok(controller)
}

fn open_source_domain_recovery_owner(
    controller_uid: u32,
) -> Result<ProtectedSourceDomainJournalOwnerV1, Box<dyn Error>> {
    let source_path = Path::new(SOURCE_DOMAIN_DIRECTORY).join(SOURCE_DOMAIN_JOURNAL);
    if !source_path.exists() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "source-domain journal absent").into());
    }
    let (owner, _) =
        ProtectedSourceDomainJournalOwnerV1::open_fixed_protected_for_uid(controller_uid)?;
    Ok(owner)
}

fn parse_binding_head(value: &str) -> io::Result<ObjectDigest> {
    let bytes = parse_hex(value, "invalid binding head")?;
    if bytes == [0; 32] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "zero binding head",
        ));
    }
    Ok(ObjectDigest::from_bytes(bytes))
}

fn binding_head_hex(binding: ObjectDigest) -> String {
    encode_hex(binding.as_bytes())
}

fn parse_cache_nonce(value: &str) -> io::Result<[u8; 16]> {
    let nonce = parse_hex(value, "invalid Cache nonce")?;
    if nonce == [0; 16] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "zero Cache nonce",
        ));
    }
    Ok(nonce)
}

fn nonce_hex(nonce: [u8; 16]) -> String {
    encode_hex(&nonce)
}

fn parse_hex<const N: usize>(value: &str, error: &'static str) -> io::Result<[u8; N]> {
    if value.len() != 2 * N {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, error));
    }
    let mut bytes = [0_u8; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let digits = std::str::from_utf8(pair)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        bytes[index] = u8::from_str_radix(digits, 16)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    }
    Ok(bytes)
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push_str(&format!("{byte:02x}"));
    }
    encoded
}

fn read_head_request(
    stream: &mut std::os::unix::net::UnixStream,
    root_custody_gate: impl FnOnce() -> Result<(), Box<dyn Error>>,
) -> Result<([u8; REQUEST_BYTES], HeadRequestMode), Box<dyn Error>> {
    let mut request = [0_u8; REQUEST_BYTES];
    stream.read_exact(&mut request)?;
    let mode = match request.get(..8) {
        Some(magic) if magic == POLICY_HEAD_QUERY_MAGIC_V2 => HeadRequestMode::Query,
        Some(magic) if magic == POLICY_HEAD_LEASE_QUERY_MAGIC_V3 => HeadRequestMode::Lease,
        Some(magic) if magic == POLICY_BINDING_QUERY_MAGIC_V4 => {
            if request[24..] == *POLICY_BINDING_HELD_MARKER_V4 {
                HeadRequestMode::QualifiedClosedBinding
            } else {
                HeadRequestMode::ClosedBinding
            }
        }
        Some(magic) if magic == POLICY_BINDING_REPLAY_QUERY_MAGIC_V5 => {
            HeadRequestMode::ClosedBindingReplay
        }
        Some(magic) if magic == ROOT_EFFECT_ACK_QUERY_MAGIC_V1 => HeadRequestMode::RootEffectAck,
        Some(magic) if magic == ROOT_EFFECT_ACK_REPLAY_QUERY_MAGIC_V1 => {
            HeadRequestMode::RootEffectAckReplay
        }
        Some(magic) if magic == POLICY_BINDING_STAGE_QUERY_MAGIC_V4 => {
            HeadRequestMode::ClosedBindingStage
        }
        Some(magic) if magic == POLICY_BINDING_PREVIEW_QUERY_MAGIC_V4 => {
            HeadRequestMode::ClosedBindingPreview
        }
        Some(magic) if magic == POLICY_BINDING_FLIGHT_QUERY_MAGIC_V4 => {
            HeadRequestMode::ClosedBindingSignerFlight
        }
        Some(magic) if magic == POLICY_BINDING_SOURCE_FLIGHT_QUERY_MAGIC_V5 => {
            HeadRequestMode::ClosedBindingSourceWriterFlight
        }
        Some(magic) if magic == POLICY_BINDING_SOURCE_FLIGHT_QUERY_MAGIC_V6 => {
            HeadRequestMode::ClosedBindingSourceWriterHeldFlight
        }
        Some(magic) if magic == POLICY_BINDING_SOURCE_FLIGHT_QUERY_MAGIC_V7 => {
            HeadRequestMode::ClosedBindingSourceWriterSignedFlight
        }
        Some(magic) if magic == POLICY_BINDING_SOURCE_FLIGHT_QUERY_MAGIC_V8 => {
            HeadRequestMode::ClosedBindingSourceWriterCasFlight
        }
        Some(magic) if magic == POLICY_BINDING_SOURCE_FLIGHT_REPLAY_QUERY_MAGIC_V7 => {
            HeadRequestMode::ClosedBindingSourceTerminalReplay
        }
        Some(magic) if magic == POLICY_BINDING_SOURCE_FLIGHT_REPLAY_QUERY_MAGIC_V8 => {
            HeadRequestMode::ClosedBindingSourceCasReplay
        }
        Some(magic) if magic == POLICY_CACHE_READBACK_QUERY_MAGIC_V5 => {
            HeadRequestMode::ClosedCacheReadback
        }
        Some(magic) if magic == POLICY_CACHE_SIGNER_QUERY_MAGIC_V6 => {
            HeadRequestMode::StagedCacheSigner
        }
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid head query").into()),
    };
    if request[24..] != [0; 8]
        && !(matches!(mode, HeadRequestMode::QualifiedClosedBinding)
            && request[24..] == *POLICY_BINDING_HELD_MARKER_V4)
    {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid head query").into());
    }
    // The bridge freezes Controller and Source only after receiving the root
    // receipt/base. Refuse Q04 before sending either frame or opening root
    // custody until all-owner currentness and recovery compose.
    if matches!(mode, HeadRequestMode::ClosedBinding) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "closed policy binding admission is unavailable",
        )
        .into());
    }
    if matches!(
        mode,
        HeadRequestMode::ClosedBindingReplay
            | HeadRequestMode::ClosedBindingStage
            | HeadRequestMode::ClosedBindingPreview
            | HeadRequestMode::ClosedBindingSignerFlight
            | HeadRequestMode::ClosedBindingSourceWriterFlight
            | HeadRequestMode::ClosedBindingSourceWriterHeldFlight
            | HeadRequestMode::ClosedBindingSourceWriterSignedFlight
            | HeadRequestMode::ClosedBindingSourceWriterCasFlight
            | HeadRequestMode::ClosedBindingSourceTerminalReplay
            | HeadRequestMode::ClosedBindingSourceCasReplay
            | HeadRequestMode::QualifiedClosedBinding
            | HeadRequestMode::RootEffectAck
            | HeadRequestMode::RootEffectAckReplay
    ) {
        if request[8..24] == [0; 16] {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "zero Q04 query nonce").into());
        }
    }
    if !matches!(
        mode,
        HeadRequestMode::ClosedBindingReplay
            | HeadRequestMode::RootEffectAck
            | HeadRequestMode::RootEffectAckReplay
            | HeadRequestMode::ClosedBindingSourceCasReplay
    ) {
        root_custody_gate()?;
    }
    Ok((request, mode))
}

fn require_controller_peer(
    stream: &std::os::unix::net::UnixStream,
    controller_uid: u32,
    controller_gid: u32,
) -> io::Result<()> {
    let peer = rustix::net::sockopt::socket_peercred(stream)?;
    if peer.uid.as_raw() != controller_uid || peer.gid.as_raw() != controller_gid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unexpected controller peer",
        ));
    }
    Ok(())
}

fn serve_current_head(
    stream: &mut std::os::unix::net::UnixStream,
    controller_uid: u32,
    controller_gid: u32,
    cache_signer_uid: u32,
    source_signer_uid: u32,
    packet: &[u8],
    inputs: &PolicyDeploymentInputsV1<'_>,
    verifying_key: &VerifyingKey,
    deployment_signer_generation: u64,
    legacy_project: Option<(&[u8], &[u8])>,
    explicit_project: Option<(&[u8], &[u8])>,
    project_key: &VerifyingKey,
    project_signer_generation: u64,
    cache_pin: Option<&[u8]>,
    source_pin: Option<&[u8]>,
    controller_hold_pin: Option<&[u8]>,
) -> Result<(), Box<dyn Error>> {
    require_controller_peer(stream, controller_uid, controller_gid)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    let (request, mode) = read_head_request(stream, || {
        require_no_fixed_closed_policy_binding_hold_v1()?;
        Ok(())
    })?;
    if matches!(mode, HeadRequestMode::ClosedBindingReplay) {
        serve_closed_binding_replay(stream, &request[8..24])?;
        return Ok(());
    }
    if matches!(mode, HeadRequestMode::RootEffectAck) {
        serve_root_effect_ack(stream, &request[8..24], controller_uid)?;
        return Ok(());
    }
    if matches!(mode, HeadRequestMode::RootEffectAckReplay) {
        serve_root_effect_ack_replay(stream, &request[8..24])?;
        return Ok(());
    }
    if matches!(mode, HeadRequestMode::ClosedBindingSourceCasReplay) {
        serve_closed_source_cas_replay_v8(stream, &request[8..24], controller_uid, controller_gid)?;
        return Ok(());
    }
    if matches!(
        mode,
        HeadRequestMode::ClosedCacheReadback | HeadRequestMode::StagedCacheSigner
    ) && request[8..24] == [0; 16]
    {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "zero Cache client nonce").into());
    }
    // Reject a cross-version request before touching the protected root head.
    let (project_packet, project_input) =
        select_project_source(mode, legacy_project, explicit_project)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
    let now_unix_seconds = i64::try_from(now.as_secs())?;
    let deployment =
        admit_fixed_policy_deployment_head_v1(packet, inputs, verifying_key, now_unix_seconds)?;
    let (selected_project_packet, selected_project_input, receipt_magic, project_expires_at) = if matches!(
        mode,
        HeadRequestMode::ClosedBinding
            | HeadRequestMode::QualifiedClosedBinding
            | HeadRequestMode::ClosedBindingStage
            | HeadRequestMode::ClosedBindingPreview
            | HeadRequestMode::ClosedBindingSignerFlight
            | HeadRequestMode::ClosedBindingSourceWriterFlight
            | HeadRequestMode::ClosedBindingSourceWriterHeldFlight
            | HeadRequestMode::ClosedBindingSourceWriterSignedFlight
            | HeadRequestMode::ClosedBindingSourceWriterCasFlight
            | HeadRequestMode::ClosedBindingSourceTerminalReplay
            | HeadRequestMode::ClosedCacheReadback
            | HeadRequestMode::StagedCacheSigner
    ) {
        let verified = verify_signed_project_policy_source_v2(
            project_packet,
            project_input,
            project_key,
            now_unix_seconds,
        )?;
        if verified.head().prerequisite_claims()[1] != deployment.packet_digest()
            || verified.head().deployment_signer_generation() != deployment_signer_generation
            || verified.head().project_signer_generation() != project_signer_generation
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "explicit project source is not current at the root",
            )
            .into());
        }
        (
            project_packet,
            project_input,
            POLICY_BINDING_RECEIPT_MAGIC_V4,
            verified.head().expires_at(),
        )
    } else {
        let verified = verify_signed_project_policy_source_v1(
            project_packet,
            project_input,
            project_key,
            now_unix_seconds,
        )?;
        if verified.head().prerequisite_claims()[1] != deployment.packet_digest() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "project deployment head mismatch",
            )
            .into());
        }
        (
            project_packet,
            project_input,
            POLICY_HEAD_RECEIPT_MAGIC_V2,
            verified.head().expires_at(),
        )
    };

    if matches!(mode, HeadRequestMode::ClosedBindingSourceTerminalReplay) {
        serve_closed_source_terminal_replay_v7(
            stream,
            &request[8..24],
            packet,
            selected_project_packet,
            selected_project_input,
            deployment_signer_generation,
            verifying_key,
            project_signer_generation,
            project_key,
            controller_uid,
            controller_gid,
            now_unix_seconds,
        )?;
        return Ok(());
    }

    if matches!(mode, HeadRequestMode::ClosedBindingPreview) {
        serve_closed_binding_preview(
            stream,
            &request[8..24],
            packet,
            selected_project_packet,
            selected_project_input,
            deployment_signer_generation,
            verifying_key,
            project_signer_generation,
            project_key,
            controller_uid,
            controller_gid,
            deployment.expires_at(),
            project_expires_at,
            now_unix_seconds,
        )?;
        return Ok(());
    }

    if matches!(
        mode,
        HeadRequestMode::ClosedBindingSignerFlight
            | HeadRequestMode::ClosedBindingSourceWriterFlight
            | HeadRequestMode::ClosedBindingSourceWriterHeldFlight
            | HeadRequestMode::ClosedBindingSourceWriterSignedFlight
            | HeadRequestMode::ClosedBindingSourceWriterCasFlight
            | HeadRequestMode::QualifiedClosedBinding
    ) {
        if cache_signer_uid == 0
            || source_signer_uid == 0
            || cache_signer_uid == controller_uid
            || source_signer_uid == controller_uid
            || source_signer_uid == cache_signer_uid
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "signer identities unavailable",
            )
            .into());
        }
        let cache_pin = cache_pin.ok_or_else(|| {
            io::Error::new(io::ErrorKind::PermissionDenied, "Cache pin unavailable")
        })?;
        let source_pin = source_pin.ok_or_else(|| {
            io::Error::new(io::ErrorKind::PermissionDenied, "Source pin unavailable")
        })?;
        if matches!(
            mode,
            HeadRequestMode::ClosedBindingSourceWriterFlight
                | HeadRequestMode::ClosedBindingSourceWriterHeldFlight
                | HeadRequestMode::ClosedBindingSourceWriterSignedFlight
                | HeadRequestMode::ClosedBindingSourceWriterCasFlight
        ) {
            serve_closed_binding_source_writer_flight_v5(
                stream,
                &request[8..24],
                packet,
                selected_project_packet,
                selected_project_input,
                deployment_signer_generation,
                verifying_key,
                project_signer_generation,
                project_key,
                controller_uid,
                controller_gid,
                cache_signer_uid,
                source_signer_uid,
                cache_pin,
                source_pin,
                deployment.expires_at(),
                project_expires_at,
                now_unix_seconds,
                matches!(
                    mode,
                    HeadRequestMode::ClosedBindingSourceWriterHeldFlight
                        | HeadRequestMode::ClosedBindingSourceWriterSignedFlight
                        | HeadRequestMode::ClosedBindingSourceWriterCasFlight
                ),
                matches!(mode, HeadRequestMode::ClosedBindingSourceWriterSignedFlight),
                matches!(mode, HeadRequestMode::ClosedBindingSourceWriterCasFlight),
                controller_hold_pin,
            )?;
            return Ok(());
        }
        serve_closed_binding_signer_flight(
            stream,
            &request[8..24],
            packet,
            selected_project_packet,
            selected_project_input,
            deployment_signer_generation,
            verifying_key,
            project_signer_generation,
            project_key,
            controller_uid,
            controller_gid,
            cache_signer_uid,
            source_signer_uid,
            cache_pin,
            source_pin,
            deployment.expires_at(),
            project_expires_at,
            now_unix_seconds,
            matches!(mode, HeadRequestMode::QualifiedClosedBinding),
        )?;
        return Ok(());
    }

    if matches!(mode, HeadRequestMode::ClosedCacheReadback) {
        let cache_pin = cache_pin.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Cache readback pin unavailable",
            )
        })?;
        serve_closed_cache_readback(
            stream,
            &request[8..24],
            packet,
            selected_project_packet,
            selected_project_input,
            cache_pin,
            deployment_signer_generation,
            verifying_key,
            project_signer_generation,
            project_key,
            controller_uid,
            deployment.expires_at(),
            project_expires_at,
        )?;
        return Ok(());
    }
    if matches!(mode, HeadRequestMode::StagedCacheSigner) {
        let cache_pin = cache_pin.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Cache signer pin unavailable",
            )
        })?;
        if cache_signer_uid == 0 || cache_signer_uid == controller_uid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "separate Cache signer identity unavailable",
            )
            .into());
        }
        serve_staged_cache_signer_readback(
            stream,
            &request[8..24],
            packet,
            selected_project_packet,
            selected_project_input,
            cache_pin,
            deployment_signer_generation,
            verifying_key,
            project_signer_generation,
            project_key,
            controller_uid,
            controller_gid,
            cache_signer_uid,
            deployment.expires_at(),
            project_expires_at,
        )?;
        return Ok(());
    }

    let mut receipt = Vec::with_capacity(MAXIMUM_RECEIPT_BYTES + EXPLICIT_PROJECT_PACKET_BYTES);
    receipt.extend_from_slice(receipt_magic);
    receipt.extend_from_slice(&request[8..24]);
    receipt.extend_from_slice(packet);
    for input in [inputs.node, inputs.site, inputs.backend, inputs.catalogs] {
        let length = u32::try_from(input.len())?;
        receipt.extend_from_slice(&length.to_be_bytes());
        receipt.extend_from_slice(input);
    }
    receipt.extend_from_slice(selected_project_packet);
    receipt.extend_from_slice(&u32::try_from(selected_project_input.len())?.to_be_bytes());
    receipt.extend_from_slice(selected_project_input);
    if matches!(mode, HeadRequestMode::ClosedBindingStage) {
        require_q04_stage_request_end(stream)?;
        check_signed_head_expiration(deployment.expires_at(), project_expires_at)?;
        let staged = with_fixed_explicit_closed_policy_binding_session_v2(
            packet,
            deployment_signer_generation,
            verifying_key,
            selected_project_packet,
            selected_project_input,
            project_signer_generation,
            project_key,
            controller_uid,
            controller_gid,
            now_unix_seconds,
            |session| session.stage_closed_binding_base(fresh_root_cache_nonce),
        )??;
        stream.write_all(&u32::try_from(receipt.len())?.to_be_bytes())?;
        stream.write_all(&receipt)?;
        write_closed_binding_stage_reply(stream, &request[8..24], staged)?;
        return Ok(());
    }
    if matches!(mode, HeadRequestMode::ClosedBinding) {
        with_fixed_explicit_closed_policy_binding_session_v2(
            packet,
            deployment_signer_generation,
            verifying_key,
            selected_project_packet,
            selected_project_input,
            project_signer_generation,
            project_key,
            controller_uid,
            controller_gid,
            now_unix_seconds,
            |session| -> io::Result<()> {
                let length = u32::try_from(receipt.len()).map_err(io::Error::other)?;
                stream.write_all(&length.to_be_bytes())?;
                stream.write_all(&receipt)?;
                write_closed_binding_base(
                    stream,
                    session.current_base().map_err(io::Error::other)?,
                )?;
                stream.set_read_timeout(Some(LEASE_ACK_TIMEOUT))?;

                let mut submission = [0_u8; CLOSED_BINDING_SUBMISSION_BYTES];
                stream.read_exact(&mut submission)?;
                let binding = decode_closed_binding_submission(&submission, &request[8..24])?;
                let committed = session
                    .commit_closed_binding(binding)
                    .map_err(io::Error::other)?;
                write_closed_binding_frame(
                    stream,
                    POLICY_BINDING_COMMITTED_MAGIC_V4,
                    &request[8..24],
                    committed.binding().as_bytes(),
                    committed.handoff_epoch(),
                )?;

                let mut acknowledgement = [0_u8; CLOSED_BINDING_ACK_BYTES];
                stream.read_exact(&mut acknowledgement)?;
                validate_closed_binding_ack(
                    &acknowledgement,
                    &request[8..24],
                    committed.binding().as_bytes(),
                    committed.handoff_epoch(),
                )?;
                check_signed_head_expiration(deployment.expires_at(), project_expires_at)?;
                complete_closed_binding_handoff_v4(
                    stream,
                    &request[8..24],
                    committed.binding().as_bytes(),
                    committed.handoff_epoch(),
                    || {
                        check_signed_head_expiration(deployment.expires_at(), project_expires_at)?;
                        session
                            .release_inert_hold(committed)
                            .map_err(io::Error::other)
                    },
                )?;
                Ok(())
            },
        )??;
        // The terminal ACK and postcommit snapshot were checked under the
        // root writer. This remains an inert observation, not an effect token.
    } else if matches!(mode, HeadRequestMode::Lease) {
        with_fixed_current_policy_head_lease_v1(packet, || -> io::Result<()> {
            let length = u32::try_from(receipt.len()).map_err(io::Error::other)?;
            stream.write_all(&length.to_be_bytes())?;
            stream.write_all(&receipt)?;
            // This protocol only permits a read-only candidate inspection;
            // it confers no binding or effect authority. A missing ACK must
            // release the root writer instead of pinning it indefinitely.
            stream.set_read_timeout(Some(LEASE_ACK_TIMEOUT))?;

            let mut acknowledgement = [0_u8; 24];
            stream.read_exact(&mut acknowledgement)?;
            validate_lease_ack(&acknowledgement, &request[8..24])?;

            check_signed_head_expiration(deployment.expires_at(), project_expires_at)
        })??;
        stream.write_all(POLICY_HEAD_LEASE_COMPLETE_MAGIC_V3)?;
        stream.write_all(&request[8..24])?;
    } else {
        stream.write_all(&receipt)?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn serve_closed_cache_readback(
    stream: &mut std::os::unix::net::UnixStream,
    client_nonce: &[u8],
    deployment_head: &[u8],
    project_head: &[u8],
    project_input: &[u8],
    cache_pin: &[u8],
    deployment_generation: u64,
    deployment_key: &VerifyingKey,
    project_generation: u64,
    project_key: &VerifyingKey,
    controller_uid: u32,
    deployment_expires: i64,
    project_expires: i64,
) -> Result<(), Box<dyn Error>> {
    let observation = with_fixed_closed_cache_readback_session_v1(
        deployment_head,
        project_head,
        project_input,
        cache_pin,
        deployment_generation,
        deployment_key,
        project_generation,
        project_key,
        controller_uid,
        fresh_root_cache_nonce,
        |challenge| {
            write_cache_challenge(stream, client_nonce, challenge)?;
            stream.set_read_timeout(Some(LEASE_ACK_TIMEOUT))?;
            let mut response = [0_u8; CLOSED_CACHE_READBACK_SUBMIT_FRAME_BYTES_V5];
            stream.read_exact(&mut response)?;
            decode_cache_response(&response, client_nonce)
        },
    )?;
    check_signed_head_expiration(deployment_expires, project_expires)?;
    stream.write_all(POLICY_CACHE_READBACK_OBSERVATION_MAGIC_V5)?;
    stream.write_all(client_nonce)?;
    stream.write_all(observation.packet_digest().as_bytes())?;
    stream.write_all(&observation.epoch().to_be_bytes())?;
    Ok(())
}

/// Settles only Root's exact packet for the authenticated Controller peer.
///
/// The RPC cannot verify the peer's local writer custody. Its caller must
/// retain those owners, and this record cannot commit AOSPCB02 or authorize
/// an effect.
#[allow(clippy::too_many_arguments)]
fn serve_staged_cache_signer_readback(
    stream: &mut std::os::unix::net::UnixStream,
    client_nonce: &[u8],
    deployment_head: &[u8],
    project_head: &[u8],
    project_input: &[u8],
    cache_pin: &[u8],
    deployment_generation: u64,
    deployment_key: &VerifyingKey,
    project_generation: u64,
    project_key: &VerifyingKey,
    controller_uid: u32,
    controller_gid: u32,
    cache_signer_uid: u32,
    deployment_expires: i64,
    project_expires: i64,
) -> Result<(), Box<dyn Error>> {
    check_signed_head_expiration(deployment_expires, project_expires)?;
    let pinned_signer = PinnedCacheOwnerReadbackSignerV1::decode(cache_pin)?;
    let challenge = stage_fixed_cache_signer_challenge_v2(
        deployment_head,
        project_head,
        project_input,
        cache_pin,
        deployment_generation,
        deployment_key,
        project_generation,
        project_key,
        controller_uid,
        fresh_root_cache_nonce,
    )?;

    // Root releases its writer before waiting for Controller. Its separate
    // signer connection later supplies an independently matched packet.
    let root_exchange =
        match begin_root_cache_signer_exchange_v2(challenge, cache_signer_uid, controller_gid) {
            Ok(exchange) => exchange,
            Err(error) => {
                // No challenge reached Controller. Revoke it before any retry;
                // an ambiguous abandonment stays fail-closed on cold replay.
                abandon_fixed_cache_signer_challenge_v2(challenge)?;
                return Err(error.into());
            }
        };
    let observed = (|| -> Result<_, Box<dyn Error>> {
        let readback = challenge.readback();
        stream.write_all(POLICY_CACHE_SIGNER_CHALLENGE_MAGIC_V6)?;
        stream.write_all(client_nonce)?;
        stream.write_all(&readback.nonce())?;
        stream.write_all(readback.cut().as_bytes())?;
        stream.write_all(&challenge.epoch().to_be_bytes())?;

        stream.set_read_timeout(Some(CACHE_SIGNER_RPC_TIMEOUT))?;
        let mut submission = [0; CLOSED_CACHE_SIGNER_SUBMIT_FRAME_BYTES_V6];
        stream.read_exact(&mut submission)?;
        let mut trailing = [0];
        if stream.read(&mut trailing)? != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "trailing V2 Cache signer submission",
            )
            .into());
        }
        let packet = decode_cache_signer_submission(&submission, client_nonce)?;
        let root_packet = root_exchange.finish(&pinned_signer, controller_uid)?;
        if packet != root_packet {
            return Err(
                io::Error::new(io::ErrorKind::InvalidData, "Cache signer peers disagree").into(),
            );
        }
        // This independent Root view must agree with the signed Cache hold
        // before historical packet settlement. It cannot prove physical-name
        // currentness or the Controller's writer lifetime.
        let root_hold = read_fixed_policy_cache_hold_v1()?;
        verify_fixed_policy_cache_owner_readback_v2(
            &packet,
            &pinned_signer,
            readback,
            controller_uid,
            root_hold.hold,
        )?;
        check_signed_head_expiration(deployment_expires, project_expires)?;
        Ok(packet)
    })();
    let packet = match observed {
        Ok(packet) => packet,
        Err(error) => {
            // No packet settlement was attempted. An ambiguous revocation
            // remains closed until its exact cold replay is resolved.
            abandon_fixed_cache_signer_challenge_v2(challenge)?;
            return Err(error);
        }
    };

    let recorded = record_fixed_cache_signer_root_settlement_v2(
        challenge,
        &packet,
        deployment_head,
        project_head,
        project_input,
        cache_pin,
        deployment_generation,
        deployment_key,
        project_generation,
        project_key,
        controller_uid,
    );
    if let Err(error) = recorded {
        // A failed commit may have reached durable storage. Reply only after
        // cold-compatible exact replay confirms that packet and epoch.
        let recovered = recover_fixed_cache_signer_root_settlement_v2(
            challenge,
            &packet,
            deployment_head,
            project_head,
            project_input,
            cache_pin,
            deployment_generation,
            deployment_key,
            project_generation,
            project_key,
            controller_uid,
        )?;
        if recovered == CacheSignerRootSettlementStateV2::Unrecorded {
            abandon_fixed_cache_signer_challenge_v2(challenge)?;
            return Err(error.into());
        }
    }
    check_signed_head_expiration(deployment_expires, project_expires)?;

    let digest = Sha256::digest(packet);
    stream.write_all(POLICY_CACHE_SIGNER_SETTLED_MAGIC_V6)?;
    stream.write_all(client_nonce)?;
    stream.write_all(&digest)?;
    stream.write_all(&challenge.epoch().to_be_bytes())?;
    Ok(())
}

fn serve_cache_signer_recovery(
    stream: &mut std::os::unix::net::UnixStream,
    client_nonce: [u8; 16],
) -> Result<(), Box<dyn Error>> {
    let mut frame = [0_u8; CLOSED_CACHE_SIGNER_RECOVERY_FRAME_BYTES_V7];
    stream.read_exact(&mut frame)?;
    let mut trailing = [0];
    if stream.read(&mut trailing)? != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "trailing Cache signer recovery query",
        )
        .into());
    }
    let (epoch, challenge, packet) = decode_cache_signer_recovery_submission_v7(&frame)?;
    let state = recover_fixed_cache_signer_root_history_v2(
        epoch,
        challenge.nonce(),
        challenge.cut(),
        packet,
    )?;
    let recovery = match state {
        CacheSignerRootSettlementStateV2::Recorded => CacheSignerRootRecoveryV7::Recorded,
        CacheSignerRootSettlementStateV2::Unrecorded => CacheSignerRootRecoveryV7::Unrecorded,
    };
    let packet_digest = ObjectDigest::from_bytes(Sha256::digest(packet).into());
    let response =
        encode_cache_signer_recovery_observation_v7(recovery, client_nonce, packet_digest, epoch);
    stream.write_all(&response)?;
    Ok(())
}

fn fresh_root_cache_nonce() -> io::Result<[u8; 16]> {
    let mut nonce = [0_u8; 16];
    let mut filled = 0;
    while filled < nonce.len() {
        let count =
            rustix::rand::getrandom(&mut nonce[filled..], rustix::rand::GetRandomFlags::empty())
                .map_err(io::Error::other)?;
        if count == 0 {
            return Err(io::Error::other("root entropy unavailable"));
        }
        filled += count;
    }
    if nonce == [0; 16] {
        return Err(io::Error::other("zero root nonce"));
    }
    Ok(nonce)
}

fn write_cache_challenge(
    stream: &mut std::os::unix::net::UnixStream,
    client_nonce: &[u8],
    challenge: ClosedCacheReadbackRootChallengeV1,
) -> io::Result<()> {
    let readback = challenge.readback();
    stream.write_all(POLICY_CACHE_READBACK_CHALLENGE_MAGIC_V5)?;
    stream.write_all(client_nonce)?;
    stream.write_all(&readback.nonce())?;
    stream.write_all(readback.cut().as_bytes())?;
    stream.write_all(&challenge.epoch().to_be_bytes())
}

fn decode_cache_response(
    response: &[u8; CLOSED_CACHE_READBACK_SUBMIT_FRAME_BYTES_V5],
    client_nonce: &[u8],
) -> io::Result<Vec<u8>> {
    if &response[..8] != POLICY_CACHE_READBACK_SUBMIT_MAGIC_V5 || &response[8..24] != client_nonce {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid closed Cache readback response",
        ));
    }
    Ok(response[24..].to_vec())
}

fn decode_cache_signer_submission(
    submission: &[u8; CLOSED_CACHE_SIGNER_SUBMIT_FRAME_BYTES_V6],
    client_nonce: &[u8],
) -> io::Result<[u8; CLOSED_CACHE_OWNER_READBACK_BYTES_V2]> {
    if &submission[..8] != POLICY_CACHE_SIGNER_SUBMIT_MAGIC_V6 || &submission[8..24] != client_nonce
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid V2 Cache signer submission",
        ));
    }
    submission[24..].try_into().map_err(io::Error::other)
}

fn validate_lease_ack(acknowledgement: &[u8; 24], nonce: &[u8]) -> io::Result<()> {
    if &acknowledgement[..8] != POLICY_HEAD_LEASE_ACK_MAGIC_V3 || &acknowledgement[8..] != nonce {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid lease acknowledgement",
        ));
    }
    Ok(())
}

fn decode_closed_binding_submission<'a>(
    submission: &'a [u8; CLOSED_BINDING_SUBMISSION_BYTES],
    nonce: &[u8],
) -> io::Result<&'a [u8]> {
    if &submission[..8] != POLICY_BINDING_SUBMIT_MAGIC_V4
        || &submission[8..24] != nonce
        || submission[24..28]
            != u32::try_from(CLOSED_POLICY_BINDING_BYTES_V2)
                .map_err(io::Error::other)?
                .to_be_bytes()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid closed binding submission",
        ));
    }
    Ok(&submission[28..])
}

fn write_closed_binding_frame(
    stream: &mut impl Write,
    magic: &[u8; 8],
    nonce: &[u8],
    binding: &[u8; 32],
    epoch: u64,
) -> io::Result<()> {
    stream.write_all(magic)?;
    stream.write_all(nonce)?;
    stream.write_all(binding)?;
    stream.write_all(&epoch.to_be_bytes())
}

fn complete_closed_binding_handoff_v4(
    stream: &mut (impl Read + Write),
    nonce: &[u8],
    binding: &[u8; 32],
    epoch: u64,
    release: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    write_closed_binding_frame(
        stream,
        POLICY_BINDING_COMPLETE_MAGIC_V4,
        nonce,
        binding,
        epoch,
    )?;

    let mut terminal_ack = [0_u8; CLOSED_BINDING_ACK_BYTES];
    stream.read_exact(&mut terminal_ack)?;
    validate_closed_binding_ack_with_magic(
        &terminal_ack,
        POLICY_BINDING_TERMINAL_ACK_MAGIC_V4,
        nonce,
        binding,
        epoch,
    )?;
    // The terminal ACK ends this one-shot connection; no trailing record may
    // be interpreted as part of the same held authority cut.
    let mut trailing = [0_u8; 1];
    if stream.read(&mut trailing)? != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "trailing closed binding acknowledgement bytes",
        ));
    }
    release()
}

fn write_closed_binding_base(
    stream: &mut std::os::unix::net::UnixStream,
    base: ClosedPolicyRootCasBaseV2,
) -> io::Result<()> {
    stream.write_all(POLICY_BINDING_BASE_MAGIC_V4)?;
    stream.write_all(&base.issuer_owner())?;
    stream.write_all(base.predecessor().as_bytes())?;
    stream.write_all(&base.next_generation().to_be_bytes())?;
    stream.write_all(&base.deployment_signer_generation().to_be_bytes())?;
    stream.write_all(&base.project_signer_generation().to_be_bytes())
}

fn write_closed_binding_stage_reply(
    stream: &mut std::os::unix::net::UnixStream,
    nonce: &[u8],
    staged: aos_sandbox::policy_compiler::StagedClosedPolicyRootBaseV2,
) -> io::Result<()> {
    let base = staged.base();
    stream.write_all(POLICY_BINDING_STAGE_REPLY_MAGIC_V4)?;
    stream.write_all(nonce)?;
    stream.write_all(&base.issuer_owner())?;
    stream.write_all(base.predecessor().as_bytes())?;
    stream.write_all(&base.next_generation().to_be_bytes())?;
    stream.write_all(&base.deployment_signer_generation().to_be_bytes())?;
    stream.write_all(&base.project_signer_generation().to_be_bytes())?;
    stream.write_all(&staged.challenge())?;
    stream.write_all(&staged.issue_epoch().to_be_bytes())
}

fn require_q04_stage_request_end(stream: &mut std::os::unix::net::UnixStream) -> io::Result<()> {
    let mut trailing = [0_u8];
    if stream.read(&mut trailing)? != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "trailing Q04 stage data",
        ));
    }
    Ok(())
}

fn validate_closed_binding_ack(
    acknowledgement: &[u8; CLOSED_BINDING_ACK_BYTES],
    nonce: &[u8],
    binding: &[u8; 32],
    handoff_epoch: u64,
) -> io::Result<()> {
    validate_closed_binding_ack_with_magic(
        acknowledgement,
        POLICY_BINDING_ACK_MAGIC_V4,
        nonce,
        binding,
        handoff_epoch,
    )
}

fn validate_closed_binding_ack_with_magic(
    acknowledgement: &[u8; CLOSED_BINDING_ACK_BYTES],
    magic: &[u8; 8],
    nonce: &[u8],
    binding: &[u8; 32],
    handoff_epoch: u64,
) -> io::Result<()> {
    if &acknowledgement[..8] != magic
        || &acknowledgement[8..24] != nonce
        || &acknowledgement[24..56] != binding
        || acknowledgement[56..64] != handoff_epoch.to_be_bytes()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid closed binding acknowledgement",
        ));
    }
    Ok(())
}

fn check_signed_head_expiration(deployment_expires: i64, project_expires: i64) -> io::Result<()> {
    let completed_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?;
    let completed_at = i64::try_from(completed_at.as_secs()).map_err(io::Error::other)?;
    if completed_at >= deployment_expires || completed_at >= project_expires {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expired policy head",
        ));
    }
    Ok(())
}

fn require_single_project_source(legacy_present: bool, explicit_present: bool) -> io::Result<()> {
    if legacy_present == explicit_present {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "exactly one project source version is required",
        ));
    }
    Ok(())
}

fn serve_closed_binding_replay(
    stream: &mut std::os::unix::net::UnixStream,
    nonce: &[u8],
) -> Result<(), Box<dyn Error>> {
    let mut claim = [0; CLOSED_BINDING_REPLAY_CLAIM_BYTES];
    stream.read_exact(&mut claim)?;
    let mut trailing = [0];
    if stream.read(&mut trailing)? != 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "trailing Q04 replay claim").into());
    }
    let binding = ObjectDigest::from_bytes(claim[..32].try_into()?);
    let epoch = u64::from_be_bytes(claim[32..40].try_into()?);
    let (decision, proposed, proof) =
        recover_fixed_closed_policy_binding_decision_v2(binding, epoch)?;
    let disposition = match decision {
        ClosedPolicyBindingDecisionV2::Absent => 0,
        ClosedPolicyBindingDecisionV2::CommittedHeld(_) => 1,
        ClosedPolicyBindingDecisionV2::CommittedReleased(_) => 2,
        ClosedPolicyBindingDecisionV2::CommittedQualifiedHeld(_) => 3,
    };

    let mut reply =
        [0; 8 + 16 + CLOSED_BINDING_REPLAY_CLAIM_BYTES + 1 + CLOSED_POLICY_BINDING_BYTES_V2 + 32];
    reply[..8].copy_from_slice(POLICY_BINDING_REPLAY_REPLY_MAGIC_V5);
    reply[8..24].copy_from_slice(nonce);
    reply[24..64].copy_from_slice(&claim);
    reply[64] = disposition;
    if let Some(proposed) = proposed {
        if proposed.len() != CLOSED_POLICY_BINDING_BYTES_V2 {
            return Err(
                io::Error::new(io::ErrorKind::InvalidData, "invalid Q04 decision record").into(),
            );
        }
        reply[65..65 + CLOSED_POLICY_BINDING_BYTES_V2].copy_from_slice(&proposed);
    }
    if let Some(proof) = proof {
        if disposition != 3 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "unexpected Q04 proof").into());
        }
        reply[65 + CLOSED_POLICY_BINDING_BYTES_V2..].copy_from_slice(proof.as_bytes());
    } else if disposition == 3 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "missing Q04 proof").into());
    }
    stream.write_all(&reply)?;
    Ok(())
}

fn read_root_effect_ack_claim(
    stream: &mut std::os::unix::net::UnixStream,
    require_end: bool,
) -> io::Result<(ObjectDigest, u64)> {
    let mut claim = [0; 40];
    stream.read_exact(&mut claim)?;
    if require_end {
        let mut trailing = [0];
        if stream.read(&mut trailing)? != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "trailing Root ACK claim",
            ));
        }
    }
    let binding = ObjectDigest::from_bytes(claim[..32].try_into().map_err(io::Error::other)?);
    let epoch = u64::from_be_bytes(claim[32..].try_into().map_err(io::Error::other)?);
    if binding.as_bytes() == &[0; 32] || epoch == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "empty Root ACK claim",
        ));
    }
    Ok((binding, epoch))
}

fn serve_root_effect_ack_replay(
    stream: &mut std::os::unix::net::UnixStream,
    client_nonce: &[u8],
) -> Result<(), Box<dyn Error>> {
    let (binding, epoch) = read_root_effect_ack_claim(stream, true)?;
    let ack = recover_fixed_closed_root_effect_ack_v1(binding, epoch)?;
    let nonce: [u8; 16] = client_nonce.try_into()?;
    stream.write_all(&encode_root_effect_ack_reply_v1(
        nonce, binding, epoch, ack,
    )?)?;
    Ok(())
}

fn serve_root_effect_ack(
    stream: &mut std::os::unix::net::UnixStream,
    client_nonce: &[u8],
    controller_uid: u32,
) -> Result<(), Box<dyn Error>> {
    let (binding, epoch) = read_root_effect_ack_claim(stream, false)?;
    let nonce: [u8; 16] = client_nonce.try_into()?;
    let controller_credential =
        read_optional_pin(Path::new(CREDENTIAL_ROOT), "controller-hold-public-key")?.ok_or_else(
            || io::Error::new(io::ErrorKind::PermissionDenied, "Controller pin absent"),
        )?;
    stream.set_read_timeout(Some(Duration::from_secs(35)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let ack = acknowledge_fixed_closed_root_effect_v1(
        binding,
        epoch,
        controller_uid,
        &controller_credential,
        |challenge| {
            let mut frame = [0; ROOT_EFFECT_ACK_CHALLENGE_FRAME_BYTES_V1];
            frame[..8].copy_from_slice(ROOT_EFFECT_ACK_CHALLENGE_MAGIC_V1);
            frame[8..24].copy_from_slice(&nonce);
            frame[24..40].copy_from_slice(&challenge.nonce());
            frame[40..72].copy_from_slice(challenge.cut().as_bytes());
            stream.write_all(&frame)?;
            read_root_effect_ack_submission(stream, nonce)
        },
    )?;
    stream.write_all(&encode_root_effect_ack_reply_v1(
        nonce,
        binding,
        epoch,
        Some(ack),
    )?)?;
    Ok(())
}

fn read_root_effect_ack_submission(
    stream: &mut std::os::unix::net::UnixStream,
    nonce: [u8; 16],
) -> io::Result<Vec<u8>> {
    let mut submit = [0; ROOT_EFFECT_ACK_SUBMIT_FRAME_BYTES_V1];
    stream.read_exact(&mut submit)?;
    let mut trailing = [0];
    if &submit[..8] != ROOT_EFFECT_ACK_SUBMIT_MAGIC_V1
        || submit[8..24] != nonce
        || stream.read(&mut trailing)? != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid Controller ACK receipt",
        ));
    }
    Ok(submit[24..].to_vec())
}

#[allow(clippy::too_many_arguments)]
fn serve_closed_binding_preview(
    stream: &mut std::os::unix::net::UnixStream,
    nonce: &[u8],
    deployment_packet: &[u8],
    project_packet: &[u8],
    project_input: &[u8],
    deployment_generation: u64,
    deployment_key: &VerifyingKey,
    project_generation: u64,
    project_key: &VerifyingKey,
    controller_uid: u32,
    controller_gid: u32,
    deployment_expires: i64,
    project_expires: i64,
    now_unix_seconds: i64,
) -> Result<(), Box<dyn Error>> {
    let (staged, proposed) = read_closed_binding_preview_claim(stream)?;
    check_signed_head_expiration(deployment_expires, project_expires)?;
    let cut = with_fixed_explicit_closed_policy_binding_session_v2(
        deployment_packet,
        deployment_generation,
        deployment_key,
        project_packet,
        project_input,
        project_generation,
        project_key,
        controller_uid,
        controller_gid,
        now_unix_seconds,
        |session| session.inspect_staged_cache_cut(&proposed, staged),
    )??;
    check_signed_head_expiration(deployment_expires, project_expires)?;

    let mut reply = [0_u8; 8 + 16 + 32 + 8 + 16 + 32 + 32];
    reply[..8].copy_from_slice(POLICY_BINDING_PREVIEW_REPLY_MAGIC_V4);
    reply[8..24].copy_from_slice(nonce);
    reply[24..56].copy_from_slice(cut.binding().as_bytes());
    reply[56..64].copy_from_slice(&cut.epoch().to_be_bytes());
    reply[64..80].copy_from_slice(cut.project().as_bytes());
    reply[80..112].copy_from_slice(cut.partition().as_bytes());
    reply[112..144].copy_from_slice(cut.cache_head().as_bytes());
    stream.write_all(&reply)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn serve_closed_source_terminal_replay_v7(
    stream: &mut std::os::unix::net::UnixStream,
    nonce: &[u8],
    deployment_packet: &[u8],
    project_packet: &[u8],
    project_input: &[u8],
    deployment_generation: u64,
    deployment_key: &VerifyingKey,
    project_generation: u64,
    project_key: &VerifyingKey,
    controller_uid: u32,
    controller_gid: u32,
    now_unix_seconds: i64,
) -> Result<(), Box<dyn Error>> {
    let digest = read_source_terminal_replay_digest_v7(stream)?;
    let record = with_fixed_explicit_closed_policy_binding_session_v2(
        deployment_packet,
        deployment_generation,
        deployment_key,
        project_packet,
        project_input,
        project_generation,
        project_key,
        controller_uid,
        controller_gid,
        now_unix_seconds,
        |session| {
            session
                .recover_current_source_terminal_digest_with_held_proof_v2(digest, controller_uid)
        },
    )??
    .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "V7 terminal row absent"))?;
    stream.write_all(POLICY_BINDING_SOURCE_FLIGHT_REPLAY_REPLY_MAGIC_V7)?;
    stream.write_all(nonce)?;
    stream.write_all(record.digest().as_bytes())?;
    Ok(())
}

fn read_source_terminal_replay_digest_v7(
    stream: &mut std::os::unix::net::UnixStream,
) -> io::Result<ObjectDigest> {
    let mut digest = [0; 32];
    stream.read_exact(&mut digest)?;
    let mut trailing = [0];
    if stream.read(&mut trailing)? != 0 || digest == [0; 32] {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid V7 replay claim").into());
    }
    Ok(ObjectDigest::from_bytes(digest))
}

fn serve_closed_source_cas_replay_v8(
    stream: &mut std::os::unix::net::UnixStream,
    nonce: &[u8],
    controller_uid: u32,
    controller_gid: u32,
) -> Result<(), Box<dyn Error>> {
    let mut claim = [0; 32 + 8 + 32];
    stream.read_exact(&mut claim)?;
    let mut trailing = [0];
    if stream.read(&mut trailing)? != 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "trailing V8 replay claim").into());
    }
    let binding = ObjectDigest::from_bytes(claim[..32].try_into()?);
    let epoch = u64::from_be_bytes(claim[32..40].try_into()?);
    let terminal = ObjectDigest::from_bytes(claim[40..].try_into()?);
    let (committed, proof, quota) = recover_fixed_committed_source_held_binding_v2(
        binding,
        epoch,
        terminal,
        controller_uid,
        controller_gid,
    )?
    .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "V8 Root CAS absent"))?;
    write_closed_source_cas_receipt_v8(
        stream,
        POLICY_BINDING_SOURCE_FLIGHT_REPLAY_REPLY_MAGIC_V8,
        nonce,
        committed.binding(),
        committed.handoff_epoch(),
        terminal,
        proof,
        quota,
    )?;
    Ok(())
}

fn write_closed_source_cas_receipt_v8(
    stream: &mut std::os::unix::net::UnixStream,
    magic: &[u8; 8],
    nonce: &[u8],
    binding: ObjectDigest,
    epoch: u64,
    terminal: ObjectDigest,
    proof: ObjectDigest,
    quota: ObjectDigest,
) -> io::Result<()> {
    if nonce.len() != 16
        || binding.as_bytes() == &[0; 32]
        || epoch == 0
        || terminal.as_bytes() == &[0; 32]
        || proof.as_bytes() == &[0; 32]
        || quota.as_bytes() == &[0; 32]
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid V8 Root receipt",
        ));
    }
    stream.write_all(magic)?;
    stream.write_all(nonce)?;
    stream.write_all(binding.as_bytes())?;
    stream.write_all(&epoch.to_be_bytes())?;
    stream.write_all(terminal.as_bytes())?;
    stream.write_all(proof.as_bytes())?;
    stream.write_all(quota.as_bytes())
}

#[allow(clippy::too_many_arguments)]
fn serve_closed_binding_source_writer_flight_v5(
    stream: &mut std::os::unix::net::UnixStream,
    nonce: &[u8],
    deployment_packet: &[u8],
    project_packet: &[u8],
    project_input: &[u8],
    deployment_generation: u64,
    deployment_key: &VerifyingKey,
    project_generation: u64,
    project_key: &VerifyingKey,
    controller_uid: u32,
    controller_gid: u32,
    cache_signer_uid: u32,
    source_signer_uid: u32,
    cache_pin: &[u8],
    source_pin: &[u8],
    deployment_expires: i64,
    project_expires: i64,
    now_unix_seconds: i64,
    held_terminal: bool,
    signed_terminal: bool,
    committed_binding: bool,
    controller_hold_pin: Option<&[u8]>,
) -> Result<(), Box<dyn Error>> {
    let (staged, proposed) = read_closed_binding_claim_frame(stream)?;
    let source_hold = read_closed_binding_flight_source_hold(stream)?;
    let cache_signer = PinnedCacheOwnerReadbackSignerV1::decode(cache_pin)?;
    let source_signer = PinnedSourceHoldReadbackSignerV1::decode(source_pin)?;
    if cache_signer.verifying_key() == source_signer.verifying_key() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "signer roles share a key").into());
    }
    check_signed_head_expiration(deployment_expires, project_expires)?;

    let reply = with_fixed_explicit_closed_policy_binding_session_v2(
        deployment_packet,
        deployment_generation,
        deployment_key,
        project_packet,
        project_input,
        project_generation,
        project_key,
        controller_uid,
        controller_gid,
        now_unix_seconds,
        |session| -> Result<_, Box<dyn Error>> {
            session.validate_staged_closed_binding_base(staged)?;
            let project = session.staged_source_project_without_cache_v5(&proposed, staged)?;
            let cache_challenge = staged_closed_policy_signer_challenge_v2(staged, &proposed)?;
            let root_cache = begin_root_q04_cache_signer_exchange_v3(
                cache_challenge,
                cache_signer_uid,
                controller_gid,
            )?;
            let (source_challenge, source_issue) = session.spend_staged_source_challenge_v1(
                &proposed,
                staged,
                fresh_root_cache_nonce,
            )?;

            let challenge_magic = if committed_binding {
                POLICY_BINDING_SOURCE_FLIGHT_CHALLENGE_MAGIC_V8
            } else if signed_terminal {
                POLICY_BINDING_SOURCE_FLIGHT_CHALLENGE_MAGIC_V7
            } else if held_terminal {
                POLICY_BINDING_SOURCE_FLIGHT_CHALLENGE_MAGIC_V6
            } else {
                POLICY_BINDING_SOURCE_FLIGHT_CHALLENGE_MAGIC_V5
            };
            stream.write_all(challenge_magic)?;
            stream.write_all(nonce)?;
            stream.write_all(&cache_challenge.nonce())?;
            stream.write_all(cache_challenge.cut().as_bytes())?;
            stream.write_all(&cache_challenge.issue_epoch().to_be_bytes())?;
            stream.write_all(&source_challenge.nonce())?;
            stream.write_all(source_challenge.cut().as_bytes())?;
            stream.write_all(&source_issue.to_be_bytes())?;
            stream.set_read_timeout(Some(CACHE_SIGNER_RPC_TIMEOUT))?;

            let (controller_packet, names) = read_source_writer_flight_submission_v5(
                stream,
                nonce,
                held_terminal,
                signed_terminal,
                committed_binding,
            )?;
            let root_packet = root_cache.finish(&cache_signer, controller_uid)?;
            if controller_packet != root_packet {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Cache signer copies differ",
                )
                .into());
            }
            let source_packet = request_root_source_signer_readback_with_names_v2(
                source_challenge,
                project,
                source_hold,
                names,
                &source_signer,
                source_signer_uid,
                controller_gid,
            )?;
            let joined = session.inspect_staged_source_writer_cut_v5(
                &proposed,
                staged,
                source_hold,
                source_challenge,
                source_issue,
                names,
                &source_packet,
                &root_packet,
                controller_uid,
            )?;
            let cut = joined.cache_cut();
            let mut reply = [0_u8; 8 + 16 + 32 + 8 + 16 + 32 + 32 + 32 + 32 + 8 + 48];
            reply[..8].copy_from_slice(if committed_binding {
                POLICY_BINDING_SOURCE_FLIGHT_REPLY_MAGIC_V8
            } else if signed_terminal {
                POLICY_BINDING_SOURCE_FLIGHT_REPLY_MAGIC_V7
            } else if held_terminal {
                POLICY_BINDING_SOURCE_FLIGHT_REPLY_MAGIC_V6
            } else {
                POLICY_BINDING_SOURCE_FLIGHT_REPLY_MAGIC_V5
            });
            reply[8..24].copy_from_slice(nonce);
            reply[24..56].copy_from_slice(cut.binding().as_bytes());
            reply[56..64].copy_from_slice(&cut.epoch().to_be_bytes());
            reply[64..80].copy_from_slice(cut.project().as_bytes());
            reply[80..112].copy_from_slice(cut.partition().as_bytes());
            reply[112..144].copy_from_slice(cut.cache_head().as_bytes());
            reply[144..176].copy_from_slice(joined.source_packet().as_bytes());
            reply[176..208].copy_from_slice(joined.cache_packet().as_bytes());
            reply[208..216].copy_from_slice(&source_issue.to_be_bytes());
            reply[216..264].copy_from_slice(&names.to_bytes());

            if signed_terminal || committed_binding {
                check_signed_head_expiration(deployment_expires, project_expires)?;
                stream.write_all(&reply)?;
                let packet = read_source_writer_flight_terminal(
                    stream,
                    nonce,
                    if committed_binding {
                        POLICY_BINDING_SOURCE_FLIGHT_TERMINAL_MAGIC_V8
                    } else {
                        POLICY_BINDING_SOURCE_FLIGHT_TERMINAL_MAGIC_V7
                    },
                )?;
                session.require_spent_source_challenge_v1(
                    &proposed,
                    staged,
                    source_challenge,
                    source_issue,
                )?;
                check_signed_head_expiration(deployment_expires, project_expires)?;
                let client_nonce: [u8; 16] = nonce.try_into().map_err(io::Error::other)?;
                let claim = ClosedSourceTerminalClaimV1::new(
                    &proposed,
                    staged,
                    source_hold,
                    source_challenge,
                    source_issue,
                    names,
                    joined.source_packet(),
                    joined.cache_packet(),
                    ObjectDigest::from_bytes(Sha256::digest(reply).into()),
                    client_nonce,
                )?;
                let pin = controller_hold_pin.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "Controller pin unavailable",
                    )
                })?;
                let record = session.record_staged_source_terminal_with_held_proof_v2(
                    claim,
                    joined,
                    controller_uid,
                    pin,
                    &packet,
                )?;
                if committed_binding {
                    let committed = session.commit_staged_source_held_binding_v2(
                        claim,
                        joined,
                        controller_uid,
                    )?;
                    let proof = record.held_proof_digest().ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "V8 held proof absent")
                    })?;
                    write_closed_source_cas_receipt_v8(
                        stream,
                        POLICY_BINDING_SOURCE_FLIGHT_DONE_MAGIC_V8,
                        nonce,
                        committed.binding(),
                        committed.handoff_epoch(),
                        record.digest(),
                        proof,
                        joined.physical_cache().quota_digest(),
                    )?;
                } else {
                    stream.write_all(POLICY_BINDING_SOURCE_FLIGHT_DONE_MAGIC_V7)?;
                    stream.write_all(nonce)?;
                    stream.write_all(record.digest().as_bytes())?;
                }
            } else if held_terminal {
                check_signed_head_expiration(deployment_expires, project_expires)?;
                stream.write_all(&reply)?;
                read_source_writer_flight_terminal_v6(stream, nonce, &reply)?;
                session.require_spent_source_challenge_v1(
                    &proposed,
                    staged,
                    source_challenge,
                    source_issue,
                )?;
                check_signed_head_expiration(deployment_expires, project_expires)?;

                stream.write_all(POLICY_BINDING_SOURCE_FLIGHT_DONE_MAGIC_V6)?;
                stream.write_all(nonce)?;
                stream.write_all(&Sha256::digest(reply))?;
            }
            Ok(reply)
        },
    )??;
    check_signed_head_expiration(deployment_expires, project_expires)?;
    if !held_terminal {
        stream.write_all(&reply)?;
    }
    Ok(())
}

fn read_source_writer_flight_submission_v5(
    stream: &mut std::os::unix::net::UnixStream,
    nonce: &[u8],
    held_terminal: bool,
    signed_terminal: bool,
    committed_binding: bool,
) -> io::Result<(
    [u8; CLOSED_CACHE_OWNER_READBACK_BYTES_V2],
    ProtectedJournalNamesV1,
)> {
    let mut submission = [0; SOURCE_FLIGHT_SUBMIT_BYTES_V5];
    stream.read_exact(&mut submission)?;
    let mut trailing = [0];
    if (!held_terminal && stream.read(&mut trailing)? != 0)
        || &submission[..8]
            != if committed_binding {
                POLICY_BINDING_SOURCE_FLIGHT_SUBMIT_MAGIC_V8
            } else if signed_terminal {
                POLICY_BINDING_SOURCE_FLIGHT_SUBMIT_MAGIC_V7
            } else if held_terminal {
                POLICY_BINDING_SOURCE_FLIGHT_SUBMIT_MAGIC_V6
            } else {
                POLICY_BINDING_SOURCE_FLIGHT_SUBMIT_MAGIC_V5
            }
        || submission[8..24] != *nonce
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid V5 flight submission",
        ));
    }
    let cache_packet = submission[24..24 + CLOSED_CACHE_OWNER_READBACK_BYTES_V2]
        .try_into()
        .map_err(io::Error::other)?;
    let names = ProtectedJournalNamesV1::from_bytes(
        &submission[24 + CLOSED_CACHE_OWNER_READBACK_BYTES_V2..],
    )
    .map_err(io::Error::other)?;
    Ok((cache_packet, names))
}

fn read_source_writer_flight_terminal_v7(
    stream: &mut std::os::unix::net::UnixStream,
    nonce: &[u8],
) -> io::Result<[u8; aos_sandbox::policy_compiler::CLOSED_CONTROLLER_HOLD_READBACK_BYTES_V1]> {
    read_source_writer_flight_terminal(
        stream,
        nonce,
        POLICY_BINDING_SOURCE_FLIGHT_TERMINAL_MAGIC_V7,
    )
}

fn read_source_writer_flight_terminal(
    stream: &mut std::os::unix::net::UnixStream,
    nonce: &[u8],
    magic: &[u8; 8],
) -> io::Result<[u8; aos_sandbox::policy_compiler::CLOSED_CONTROLLER_HOLD_READBACK_BYTES_V1]> {
    const PACKET_BYTES: usize =
        aos_sandbox::policy_compiler::CLOSED_CONTROLLER_HOLD_READBACK_BYTES_V1;
    let mut terminal = [0; 8 + 16 + PACKET_BYTES];
    stream.read_exact(&mut terminal)?;
    let mut trailing = [0];
    if stream.read(&mut trailing)? != 0 || &terminal[..8] != magic || terminal[8..24] != *nonce {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid signed V7 terminal",
        ));
    }
    terminal[24..].try_into().map_err(io::Error::other)
}

fn read_source_writer_flight_terminal_v6(
    stream: &mut std::os::unix::net::UnixStream,
    nonce: &[u8],
    reply: &[u8],
) -> io::Result<()> {
    let mut terminal = [0; 8 + 16 + 32];
    stream.read_exact(&mut terminal)?;
    let mut trailing = [0];
    if stream.read(&mut trailing)? != 0
        || &terminal[..8] != POLICY_BINDING_SOURCE_FLIGHT_TERMINAL_MAGIC_V6
        || terminal[8..24] != *nonce
        || terminal[24..] != Sha256::digest(reply)[..]
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid V6 terminal postflight ACK",
        ));
    }
    Ok(())
}

fn serve_closed_binding_signer_flight(
    stream: &mut std::os::unix::net::UnixStream,
    nonce: &[u8],
    deployment_packet: &[u8],
    project_packet: &[u8],
    project_input: &[u8],
    deployment_generation: u64,
    deployment_key: &VerifyingKey,
    project_generation: u64,
    project_key: &VerifyingKey,
    controller_uid: u32,
    controller_gid: u32,
    cache_signer_uid: u32,
    source_signer_uid: u32,
    cache_pin: &[u8],
    source_pin: &[u8],
    deployment_expires: i64,
    project_expires: i64,
    now_unix_seconds: i64,
    commit: bool,
) -> Result<(), Box<dyn Error>> {
    let (staged, proposed) = read_closed_binding_claim_frame(stream)?;
    let source_hold = read_closed_binding_flight_source_hold(stream)?;
    let cache_signer = PinnedCacheOwnerReadbackSignerV1::decode(cache_pin)?;
    let source_signer = PinnedSourceHoldReadbackSignerV1::decode(source_pin)?;
    if cache_signer.verifying_key() == source_signer.verifying_key() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "signer roles share a key").into());
    }
    check_signed_head_expiration(deployment_expires, project_expires)?;

    // Root remains the last writer, including both independent signer RPCs.
    let (joined, committed) = with_fixed_explicit_closed_policy_binding_session_v2(
        deployment_packet,
        deployment_generation,
        deployment_key,
        project_packet,
        project_input,
        project_generation,
        project_key,
        controller_uid,
        controller_gid,
        now_unix_seconds,
        |session| -> Result<_, Box<dyn Error>> {
            session.validate_staged_closed_binding_base(staged)?;
            let cut = session.prepare_cache_cut(&proposed)?;
            let challenge = staged_closed_policy_signer_challenge_v2(staged, &proposed)?;
            let root_cache = begin_root_q04_cache_signer_exchange_v3(
                challenge,
                cache_signer_uid,
                controller_gid,
            )?;

            stream.write_all(POLICY_BINDING_FLIGHT_CHALLENGE_MAGIC_V4)?;
            stream.write_all(nonce)?;
            stream.write_all(&challenge.nonce())?;
            stream.write_all(challenge.cut().as_bytes())?;
            stream.write_all(&challenge.issue_epoch().to_be_bytes())?;
            stream.set_read_timeout(Some(CACHE_SIGNER_RPC_TIMEOUT))?;

            let controller_packet = read_closed_binding_flight_submission(stream, nonce)?;
            let root_packet = root_cache.finish(&cache_signer, controller_uid)?;
            if controller_packet != root_packet {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Cache signer copies differ",
                )
                .into());
            }
            let source_packet = request_root_staged_q04_source_readback_v2(
                challenge,
                cut.project(),
                source_hold,
                &source_signer,
                source_signer_uid,
                controller_gid,
            )?;
            if commit {
                // The signed heads must still be live at the durable decision.
                check_signed_head_expiration(deployment_expires, project_expires)?;
                let committed = session.commit_qualified_staged_closed_binding(
                    &proposed,
                    staged,
                    source_hold,
                    &source_packet,
                    &root_packet,
                    controller_uid,
                )?;
                Ok((None, Some(committed)))
            } else {
                let joined = session.inspect_staged_signer_cut(
                    &proposed,
                    staged,
                    source_hold,
                    &source_packet,
                    &root_packet,
                    controller_uid,
                )?;
                Ok((Some(joined), None))
            }
        },
    )??;
    if let Some(committed) = committed {
        // No ACK/release exists on this held-CAS exchange. An ambiguous reply
        // is resolved only by the exact protected Root decision replay.
        let mut reply = [0_u8; 8 + 16 + 32 + 8];
        reply[..8].copy_from_slice(POLICY_BINDING_COMMITTED_MAGIC_V4);
        reply[8..24].copy_from_slice(nonce);
        reply[24..56].copy_from_slice(committed.binding().as_bytes());
        reply[56..64].copy_from_slice(&committed.handoff_epoch().to_be_bytes());
        stream.write_all(&reply)?;
        return Ok(());
    }
    check_signed_head_expiration(deployment_expires, project_expires)?;

    let joined = joined.ok_or_else(|| io::Error::other("missing inert signer join"))?;
    let cut = joined.cache_cut();
    let mut reply = [0_u8; 8 + 16 + 32 + 8 + 16 + 32 + 32 + 32 + 32];
    reply[..8].copy_from_slice(POLICY_BINDING_FLIGHT_REPLY_MAGIC_V4);
    reply[8..24].copy_from_slice(nonce);
    reply[24..56].copy_from_slice(cut.binding().as_bytes());
    reply[56..64].copy_from_slice(&cut.epoch().to_be_bytes());
    reply[64..80].copy_from_slice(cut.project().as_bytes());
    reply[80..112].copy_from_slice(cut.partition().as_bytes());
    reply[112..144].copy_from_slice(cut.cache_head().as_bytes());
    reply[144..176].copy_from_slice(joined.source_packet().as_bytes());
    reply[176..208].copy_from_slice(joined.cache_packet().as_bytes());
    stream.write_all(&reply)?;
    Ok(())
}

fn read_closed_binding_flight_submission(
    stream: &mut std::os::unix::net::UnixStream,
    nonce: &[u8],
) -> io::Result<[u8; CLOSED_CACHE_OWNER_READBACK_BYTES_V2]> {
    let mut submission = [0; CLOSED_BINDING_FLIGHT_SUBMIT_BYTES];
    stream.read_exact(&mut submission)?;
    let mut trailing = [0];
    if stream.read(&mut trailing)? != 0
        || &submission[..8] != POLICY_BINDING_FLIGHT_SUBMIT_MAGIC_V4
        || submission[8..24] != *nonce
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid held-flight submission",
        ));
    }
    submission[24..].try_into().map_err(io::Error::other)
}

fn read_closed_binding_flight_source_hold(
    stream: &mut std::os::unix::net::UnixStream,
) -> io::Result<SourceDomainPolicyHoldV1> {
    let mut bytes = [0_u8; CLOSED_BINDING_FLIGHT_HOLD_BYTES];
    stream.read_exact(&mut bytes)?;
    SourceDomainPolicyHoldV1::new(
        OperationId::from_bytes(bytes[..16].try_into().map_err(io::Error::other)?),
        SandboxId::from_bytes(bytes[16..32].try_into().map_err(io::Error::other)?),
        ObjectDigest::from_bytes(bytes[32..64].try_into().map_err(io::Error::other)?),
        ObjectDigest::from_bytes(bytes[64..96].try_into().map_err(io::Error::other)?),
        ObjectDigest::from_bytes(bytes[96..128].try_into().map_err(io::Error::other)?),
        u64::from_be_bytes(bytes[128..136].try_into().map_err(io::Error::other)?),
    )
    .map_err(io::Error::other)
}

fn read_closed_binding_preview_claim(
    stream: &mut std::os::unix::net::UnixStream,
) -> io::Result<(
    StagedClosedPolicyRootBaseV2,
    [u8; CLOSED_POLICY_BINDING_BYTES_V2],
)> {
    let parsed = read_closed_binding_claim_frame(stream)?;
    let mut trailing = [0_u8];
    if stream.read(&mut trailing)? != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "trailing Q04 preview data",
        ));
    }
    Ok(parsed)
}

fn read_closed_binding_claim_frame(
    stream: &mut std::os::unix::net::UnixStream,
) -> io::Result<(
    StagedClosedPolicyRootBaseV2,
    [u8; CLOSED_POLICY_BINDING_BYTES_V2],
)> {
    let mut claim = [0_u8; CLOSED_BINDING_PREVIEW_CLAIM_BYTES];
    stream.read_exact(&mut claim)?;
    let issuer_owner = claim[..16].try_into().map_err(io::Error::other)?;
    let predecessor = ObjectDigest::from_bytes(claim[16..48].try_into().map_err(io::Error::other)?);
    let next_generation = u64::from_be_bytes(claim[48..56].try_into().map_err(io::Error::other)?);
    let deployment_generation =
        u64::from_be_bytes(claim[56..64].try_into().map_err(io::Error::other)?);
    let project_generation =
        u64::from_be_bytes(claim[64..72].try_into().map_err(io::Error::other)?);
    let challenge = claim[72..88].try_into().map_err(io::Error::other)?;
    let issue_epoch = u64::from_be_bytes(claim[88..96].try_into().map_err(io::Error::other)?);
    let base = ClosedPolicyRootCasBaseV2::from_untrusted_remote_fields(
        issuer_owner,
        predecessor,
        next_generation,
        deployment_generation,
        project_generation,
    )
    .map_err(io::Error::other)?;
    let staged =
        StagedClosedPolicyRootBaseV2::from_untrusted_remote_fields(base, challenge, issue_epoch)
            .map_err(io::Error::other)?;
    let proposed = claim[96..].try_into().map_err(io::Error::other)?;
    Ok((staged, proposed))
}

fn select_project_source<'a>(
    mode: HeadRequestMode,
    legacy: Option<(&'a [u8], &'a [u8])>,
    explicit: Option<(&'a [u8], &'a [u8])>,
) -> io::Result<(&'a [u8], &'a [u8])> {
    match mode {
        HeadRequestMode::ClosedBinding
        | HeadRequestMode::QualifiedClosedBinding
        | HeadRequestMode::ClosedBindingStage
        | HeadRequestMode::ClosedBindingPreview
        | HeadRequestMode::ClosedBindingSignerFlight
        | HeadRequestMode::ClosedBindingSourceWriterFlight
        | HeadRequestMode::ClosedBindingSourceWriterHeldFlight
        | HeadRequestMode::ClosedBindingSourceWriterSignedFlight
        | HeadRequestMode::ClosedBindingSourceWriterCasFlight
        | HeadRequestMode::ClosedBindingSourceTerminalReplay
        | HeadRequestMode::ClosedCacheReadback
        | HeadRequestMode::StagedCacheSigner => explicit.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "explicit project source is unavailable",
            )
        }),
        HeadRequestMode::Query | HeadRequestMode::Lease => legacy.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "legacy project source is unavailable",
            )
        }),
        HeadRequestMode::ClosedBindingReplay
        | HeadRequestMode::RootEffectAck
        | HeadRequestMode::RootEffectAckReplay
        | HeadRequestMode::ClosedBindingSourceCasReplay => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "held Q04 recovery has no project source",
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::io::Cursor;
    use std::os::unix::net::UnixStream;

    use super::*;

    #[test]
    fn historical_cache_recovery_is_only_on_the_separate_endpoint() {
        let (mut client, mut server) = UnixStream::pair().expect("local policy socket");
        let mut request = [0_u8; REQUEST_BYTES];
        request[..8].copy_from_slice(POLICY_CACHE_SIGNER_RECOVERY_QUERY_MAGIC_V7);
        request[8..24].copy_from_slice(&[1; 16]);
        client.write_all(&request).expect("recovery query");

        let admission_opened = Cell::new(false);
        assert!(
            read_head_request(&mut server, || {
                admission_opened.set(true);
                Ok(())
            })
            .is_err()
        );
        assert!(!admission_opened.get());

        let (mut client, mut server) = UnixStream::pair().expect("recovery socket");
        client.write_all(&request).expect("recovery-only query");
        assert_eq!(
            read_cache_signer_recovery_header(&mut server).expect("exact recovery header"),
            request
        );
        request[8..24].fill(0);
        let (mut client, mut server) = UnixStream::pair().expect("recovery socket");
        client.write_all(&request).expect("zero nonce query");
        assert!(read_cache_signer_recovery_header(&mut server).is_err());
    }

    #[test]
    fn recovery_only_endpoint_rejects_foreign_peer_before_root_custody() {
        let (_client, mut server) = UnixStream::pair().expect("recovery socket");
        let uid = rustix::process::getuid().as_raw();
        let gid = rustix::process::getgid().as_raw();
        let error = serve_cache_signer_recovery_request(&mut server, uid + 1, gid)
            .err()
            .expect("foreign peer");
        assert_eq!(
            error.downcast_ref::<io::Error>().map(io::Error::kind),
            Some(io::ErrorKind::PermissionDenied)
        );
    }

    #[test]
    fn q04_request_emits_no_receipt_and_does_not_open_root_custody() {
        let directory = tempfile::tempdir().expect("root journal fixture");
        let journal_path = directory.path().join("policy-authority.journal");
        std::fs::write(&journal_path, b"root journal before request")
            .expect("root journal fixture");
        let (mut client, mut server) = UnixStream::pair().expect("local policy socket");
        let mut request = [0_u8; REQUEST_BYTES];
        request[..8].copy_from_slice(POLICY_BINDING_QUERY_MAGIC_V4);
        request[8..24].copy_from_slice(&[1; 16]);
        client.write_all(&request).expect("Q04 request");

        let root_custody_opened = Cell::new(false);
        let error = read_head_request(&mut server, || {
            root_custody_opened.set(true);
            std::fs::write(&journal_path, b"root journal changed")?;
            Ok(())
        })
        .err()
        .expect("Q04 stays closed");
        assert_eq!(
            error.downcast_ref::<io::Error>().map(io::Error::kind),
            Some(io::ErrorKind::PermissionDenied)
        );
        assert!(!root_custody_opened.get());
        assert_eq!(
            std::fs::read(&journal_path)
                .expect("unchanged root journal")
                .as_slice(),
            b"root journal before request"
        );
        drop(server);
        let mut response = Vec::new();
        client.read_to_end(&mut response).expect("closed response");
        assert!(response.is_empty());
    }

    #[test]
    fn q04_held_flight_requires_root_gate_and_exact_source_hold_frame() {
        let (mut client, mut server) = UnixStream::pair().expect("local policy socket");
        let mut request = [0_u8; REQUEST_BYTES];
        request[..8].copy_from_slice(POLICY_BINDING_FLIGHT_QUERY_MAGIC_V4);
        request[8..24].copy_from_slice(&[7; 16]);
        client.write_all(&request).expect("flight query");
        let gate = Cell::new(false);
        let (_, mode) = read_head_request(&mut server, || {
            gate.set(true);
            Ok(())
        })
        .expect("inert flight request");
        assert!(gate.get());
        assert!(matches!(mode, HeadRequestMode::ClosedBindingSignerFlight));

        let (mut zero_client, mut zero_server) = UnixStream::pair().expect("local policy socket");
        request[8..24].fill(0);
        zero_client
            .write_all(&request)
            .expect("zero-nonce flight query");
        let opened = Cell::new(false);
        assert!(
            read_head_request(&mut zero_server, || {
                opened.set(true);
                Ok(())
            })
            .is_err()
        );
        assert!(!opened.get());

        let mut hold = [0_u8; CLOSED_BINDING_FLIGHT_HOLD_BYTES];
        hold[..16].fill(1);
        hold[16..32].fill(2);
        hold[32..64].fill(3);
        hold[64..96].fill(4);
        hold[96..128].fill(5);
        hold[128..136].copy_from_slice(&6_u64.to_be_bytes());
        client.write_all(&hold).expect("source hold claim");
        let parsed = read_closed_binding_flight_source_hold(&mut server).expect("typed hold");
        assert_eq!(parsed.epoch(), 6);
        assert_eq!(parsed.binding(), ObjectDigest::from_bytes([5; 32]));

        hold[96..128].fill(0);
        client.write_all(&hold).expect("invalid source hold");
        assert!(read_closed_binding_flight_source_hold(&mut server).is_err());
    }

    #[test]
    fn v5_source_flight_is_distinct_and_requires_exact_writer_names() {
        let nonce = [7; 16];
        let (mut client, mut server) = UnixStream::pair().expect("local policy socket");
        let mut request = [0_u8; REQUEST_BYTES];
        request[..8].copy_from_slice(POLICY_BINDING_SOURCE_FLIGHT_QUERY_MAGIC_V5);
        request[8..24].copy_from_slice(&nonce);
        client.write_all(&request).expect("V5 flight query");
        let opened = Cell::new(false);
        let (_, mode) = read_head_request(&mut server, || {
            opened.set(true);
            Ok(())
        })
        .expect("exact V5 query");
        assert!(opened.get());
        assert!(matches!(
            mode,
            HeadRequestMode::ClosedBindingSourceWriterFlight
        ));
        let (mut zero_client, mut zero_server) = UnixStream::pair().expect("local policy socket");
        request[8..24].fill(0);
        zero_client.write_all(&request).expect("zero V5 query");
        let opened = Cell::new(false);
        assert!(
            read_head_request(&mut zero_server, || {
                opened.set(true);
                Ok(())
            })
            .is_err()
        );
        assert!(!opened.get());

        let mut names_bytes = [0; 48];
        for (index, chunk) in names_bytes.chunks_exact_mut(8).enumerate() {
            chunk.copy_from_slice(&(index as u64 + 1).to_be_bytes());
        }
        let names = ProtectedJournalNamesV1::from_bytes(&names_bytes).unwrap();
        let mut submission = [0; SOURCE_FLIGHT_SUBMIT_BYTES_V5];
        submission[..8].copy_from_slice(POLICY_BINDING_SOURCE_FLIGHT_SUBMIT_MAGIC_V5);
        submission[8..24].copy_from_slice(&nonce);
        submission[24..24 + CLOSED_CACHE_OWNER_READBACK_BYTES_V2].fill(11);
        submission[24 + CLOSED_CACHE_OWNER_READBACK_BYTES_V2..].copy_from_slice(&names_bytes);
        let parse = |bytes: &[u8]| {
            let (mut client, mut server) = UnixStream::pair().expect("flight pair");
            client.write_all(bytes).expect("flight bytes");
            client
                .shutdown(std::net::Shutdown::Write)
                .expect("request EOF");
            read_source_writer_flight_submission_v5(&mut server, &nonce, false, false, false)
        };
        let (packet, parsed_names) = parse(&submission).expect("exact V5 submission");
        assert_eq!(packet, [11; CLOSED_CACHE_OWNER_READBACK_BYTES_V2]);
        assert_eq!(parsed_names, names);

        for offset in [0, 8, 24 + CLOSED_CACHE_OWNER_READBACK_BYTES_V2 + 7] {
            let mut changed = submission;
            changed[offset] = 0;
            assert!(parse(&changed).is_err());
        }
        let mut trailing = submission.to_vec();
        trailing.push(0);
        assert!(parse(&trailing).is_err());
        assert!(parse(&submission[..submission.len() - 1]).is_err());
    }

    #[test]
    fn v6_source_flight_requires_distinct_mode_and_exact_terminal_ack() {
        let nonce = [7; 16];
        let (mut client, mut server) = UnixStream::pair().expect("local policy socket");
        let mut request = [0_u8; REQUEST_BYTES];
        request[..8].copy_from_slice(POLICY_BINDING_SOURCE_FLIGHT_QUERY_MAGIC_V6);
        request[8..24].copy_from_slice(&nonce);
        client.write_all(&request).expect("V6 query");
        let (_, mode) = read_head_request(&mut server, || Ok(())).expect("distinct V6 query");
        assert!(matches!(
            mode,
            HeadRequestMode::ClosedBindingSourceWriterHeldFlight
        ));
        let (mut zero_client, mut zero_server) = UnixStream::pair().expect("local policy socket");
        request[8..24].fill(0);
        zero_client.write_all(&request).expect("zero V6 query");
        assert!(read_head_request(&mut zero_server, || Ok(())).is_err());

        let mut names_bytes = [0; 48];
        for (index, chunk) in names_bytes.chunks_exact_mut(8).enumerate() {
            chunk.copy_from_slice(&(index as u64 + 1).to_be_bytes());
        }
        let mut submission = [0; SOURCE_FLIGHT_SUBMIT_BYTES_V5];
        submission[..8].copy_from_slice(POLICY_BINDING_SOURCE_FLIGHT_SUBMIT_MAGIC_V6);
        submission[8..24].copy_from_slice(&nonce);
        submission[24..24 + CLOSED_CACHE_OWNER_READBACK_BYTES_V2].fill(11);
        submission[24 + CLOSED_CACHE_OWNER_READBACK_BYTES_V2..].copy_from_slice(&names_bytes);
        client
            .write_all(&submission)
            .expect("V6 submission without EOF");
        let (_, names) =
            read_source_writer_flight_submission_v5(&mut server, &nonce, true, false, false)
                .expect("V6 submission while connection remains writable");
        assert_eq!(names.to_bytes(), names_bytes);

        let reply = [13; 264];
        let mut terminal = [0; 56];
        terminal[..8].copy_from_slice(POLICY_BINDING_SOURCE_FLIGHT_TERMINAL_MAGIC_V6);
        terminal[8..24].copy_from_slice(&nonce);
        terminal[24..].copy_from_slice(&Sha256::digest(reply));
        client.write_all(&terminal).expect("terminal ACK");
        client.shutdown(std::net::Shutdown::Write).expect("ACK EOF");
        read_source_writer_flight_terminal_v6(&mut server, &nonce, &reply)
            .expect("exact terminal ACK");

        for offset in [0, 8, 24, 55] {
            let (mut client, mut server) = UnixStream::pair().expect("local pair");
            let mut altered = terminal;
            altered[offset] ^= 1;
            client.write_all(&altered).expect("altered ACK");
            client.shutdown(std::net::Shutdown::Write).expect("ACK EOF");
            assert!(read_source_writer_flight_terminal_v6(&mut server, &nonce, &reply).is_err());
        }
        let (mut client, mut server) = UnixStream::pair().expect("local pair");
        client.write_all(&terminal).expect("terminal ACK");
        client.write_all(&[0]).expect("trailing byte");
        client.shutdown(std::net::Shutdown::Write).expect("ACK EOF");
        assert!(read_source_writer_flight_terminal_v6(&mut server, &nonce, &reply).is_err());
    }

    #[test]
    fn v7_signed_terminal_and_replay_have_distinct_bounded_frames() {
        let nonce = [7; 16];
        for (magic, expected) in [
            (
                POLICY_BINDING_SOURCE_FLIGHT_QUERY_MAGIC_V7,
                HeadRequestMode::ClosedBindingSourceWriterSignedFlight,
            ),
            (
                POLICY_BINDING_SOURCE_FLIGHT_REPLAY_QUERY_MAGIC_V7,
                HeadRequestMode::ClosedBindingSourceTerminalReplay,
            ),
        ] {
            let (mut client, mut server) = UnixStream::pair().expect("local socket");
            let mut request = [0; REQUEST_BYTES];
            request[..8].copy_from_slice(magic);
            request[8..24].copy_from_slice(&nonce);
            client.write_all(&request).expect("V7 query");
            let (_, mode) = read_head_request(&mut server, || Ok(())).expect("V7 mode");
            assert!(std::mem::discriminant(&mode) == std::mem::discriminant(&expected));

            let (mut client, mut server) = UnixStream::pair().expect("local socket");
            request[8..24].fill(0);
            client.write_all(&request).expect("zero V7 query");
            assert!(read_head_request(&mut server, || Ok(())).is_err());
        }

        let mut names_bytes = [0; 48];
        for (index, chunk) in names_bytes.chunks_exact_mut(8).enumerate() {
            chunk.copy_from_slice(&(index as u64 + 1).to_be_bytes());
        }
        let (mut client, mut server) = UnixStream::pair().expect("local socket");
        let mut submission = [0; SOURCE_FLIGHT_SUBMIT_BYTES_V5];
        submission[..8].copy_from_slice(POLICY_BINDING_SOURCE_FLIGHT_SUBMIT_MAGIC_V7);
        submission[8..24].copy_from_slice(&nonce);
        submission[24..24 + CLOSED_CACHE_OWNER_READBACK_BYTES_V2].fill(11);
        submission[24 + CLOSED_CACHE_OWNER_READBACK_BYTES_V2..].copy_from_slice(&names_bytes);
        client.write_all(&submission).expect("V7 submission");
        assert_eq!(
            read_source_writer_flight_submission_v5(&mut server, &nonce, true, true, false)
                .expect("held V7 submission")
                .1
                .to_bytes(),
            names_bytes
        );

        let mut terminal = [0; 8 + 16 + 248];
        terminal[..8].copy_from_slice(POLICY_BINDING_SOURCE_FLIGHT_TERMINAL_MAGIC_V7);
        terminal[8..24].copy_from_slice(&nonce);
        terminal[24..].fill(29);
        let (mut client, mut server) = UnixStream::pair().expect("local socket");
        client.write_all(&terminal).expect("signed terminal");
        client.shutdown(std::net::Shutdown::Write).expect("EOF");
        assert_eq!(
            read_source_writer_flight_terminal_v7(&mut server, &nonce).expect("exact signed frame"),
            [29; 248]
        );
        for offset in [0, 8] {
            let (mut client, mut server) = UnixStream::pair().expect("local socket");
            let mut altered = terminal;
            altered[offset] ^= 1;
            client.write_all(&altered).expect("altered terminal");
            client.shutdown(std::net::Shutdown::Write).expect("EOF");
            assert!(read_source_writer_flight_terminal_v7(&mut server, &nonce).is_err());
        }
        let (mut client, mut server) = UnixStream::pair().expect("local socket");
        client.write_all(&terminal).expect("signed terminal");
        client.write_all(&[0]).expect("trailing byte");
        client.shutdown(std::net::Shutdown::Write).expect("EOF");
        assert!(read_source_writer_flight_terminal_v7(&mut server, &nonce).is_err());

        for (digest, trailing, valid) in [
            ([9; 32], false, true),
            ([0; 32], false, false),
            ([9; 32], true, false),
        ] {
            let (mut client, mut server) = UnixStream::pair().expect("local socket");
            client.write_all(&digest).expect("replay digest");
            if trailing {
                client.write_all(&[0]).expect("trailing byte");
            }
            client.shutdown(std::net::Shutdown::Write).expect("EOF");
            assert_eq!(
                read_source_terminal_replay_digest_v7(&mut server).is_ok(),
                valid
            );
        }
    }

    #[test]
    fn v8_cas_flight_and_recovery_use_distinct_held_frames() {
        let nonce = [17; 16];
        for (magic, expected, opens_root) in [
            (POLICY_BINDING_SOURCE_FLIGHT_QUERY_MAGIC_V8, true, true),
            (
                POLICY_BINDING_SOURCE_FLIGHT_REPLAY_QUERY_MAGIC_V8,
                false,
                false,
            ),
        ] {
            let (mut client, mut server) = UnixStream::pair().expect("V8 request pair");
            let mut request = [0; REQUEST_BYTES];
            request[..8].copy_from_slice(magic);
            request[8..24].copy_from_slice(&nonce);
            client.write_all(&request).expect("V8 query");
            let opened = Cell::new(false);
            let (_, mode) = read_head_request(&mut server, || {
                opened.set(true);
                if opens_root {
                    Ok(())
                } else {
                    Err(io::Error::new(io::ErrorKind::PermissionDenied, "held").into())
                }
            })
            .expect("versioned V8 query");
            assert_eq!(opened.get(), opens_root);
            assert_eq!(
                matches!(mode, HeadRequestMode::ClosedBindingSourceWriterCasFlight),
                expected
            );
        }

        let (mut client, mut server) = UnixStream::pair().expect("V8 terminal pair");
        let mut terminal =
            [0; 8 + 16 + aos_sandbox::policy_compiler::CLOSED_CONTROLLER_HOLD_READBACK_BYTES_V1];
        terminal[..8].copy_from_slice(POLICY_BINDING_SOURCE_FLIGHT_TERMINAL_MAGIC_V8);
        terminal[8..24].copy_from_slice(&nonce);
        terminal[24..].fill(21);
        client.write_all(&terminal).expect("V8 terminal");
        client
            .shutdown(std::net::Shutdown::Write)
            .expect("terminal EOF");
        assert_eq!(
            read_source_writer_flight_terminal(
                &mut server,
                &nonce,
                POLICY_BINDING_SOURCE_FLIGHT_TERMINAL_MAGIC_V8
            )
            .expect("exact V8 terminal"),
            [21; aos_sandbox::policy_compiler::CLOSED_CONTROLLER_HOLD_READBACK_BYTES_V1]
        );
        let (mut client, mut server) = UnixStream::pair().expect("cross-version pair");
        client.write_all(&terminal).expect("V8 terminal");
        client
            .shutdown(std::net::Shutdown::Write)
            .expect("terminal EOF");
        assert!(read_source_writer_flight_terminal_v7(&mut server, &nonce).is_err());

        let (mut client, mut server) = UnixStream::pair().expect("V8 receipt pair");
        write_closed_source_cas_receipt_v8(
            &mut server,
            POLICY_BINDING_SOURCE_FLIGHT_DONE_MAGIC_V8,
            &nonce,
            ObjectDigest::from_bytes([1; 32]),
            4,
            ObjectDigest::from_bytes([2; 32]),
            ObjectDigest::from_bytes([3; 32]),
            ObjectDigest::from_bytes([4; 32]),
        )
        .expect("bounded completion");
        let mut receipt = [0; 160];
        client.read_exact(&mut receipt).expect("complete receipt");
        assert_eq!(&receipt[..8], POLICY_BINDING_SOURCE_FLIGHT_DONE_MAGIC_V8);
        assert_eq!(&receipt[96..128], &[3; 32]);
        assert_eq!(&receipt[128..], &[4; 32]);
        assert!(
            write_closed_source_cas_receipt_v8(
                &mut server,
                POLICY_BINDING_SOURCE_FLIGHT_DONE_MAGIC_V8,
                &nonce,
                ObjectDigest::from_bytes([1; 32]),
                4,
                ObjectDigest::from_bytes([2; 32]),
                ObjectDigest::from_bytes([0; 32]),
                ObjectDigest::from_bytes([4; 32]),
            )
            .is_err()
        );
    }

    #[test]
    fn q04_held_marker_requires_exact_version_and_fresh_nonce() {
        let (mut client, mut server) = UnixStream::pair().expect("local policy socket");
        let mut request = [0_u8; REQUEST_BYTES];
        request[..8].copy_from_slice(POLICY_BINDING_QUERY_MAGIC_V4);
        request[8..24].copy_from_slice(&[7; 16]);
        request[24..].copy_from_slice(POLICY_BINDING_HELD_MARKER_V4);
        client.write_all(&request).expect("held-cut request");
        let opened = Cell::new(false);
        let (_, mode) = read_head_request(&mut server, || {
            opened.set(true);
            Ok(())
        })
        .expect("exact held marker");
        assert!(opened.get());
        assert!(matches!(mode, HeadRequestMode::QualifiedClosedBinding));

        for offset in [8, 24] {
            let (mut client, mut server) = UnixStream::pair().expect("local policy socket");
            let mut changed = request;
            if offset == 8 {
                changed[8..24].fill(0);
            } else {
                changed[offset] ^= 1;
            }
            client.write_all(&changed).expect("invalid held request");
            let opened = Cell::new(false);
            assert!(
                read_head_request(&mut server, || {
                    opened.set(true);
                    Ok(())
                })
                .is_err()
            );
            assert!(!opened.get());
        }
    }

    #[test]
    fn q04_held_flight_submission_rejects_foreign_nonce_and_trailing_bytes() {
        let mut frame = [0_u8; CLOSED_BINDING_FLIGHT_SUBMIT_BYTES];
        frame[..8].copy_from_slice(POLICY_BINDING_FLIGHT_SUBMIT_MAGIC_V4);
        frame[8..24].fill(7);
        frame[24..].fill(9);

        let read = |bytes: &[u8], nonce: &[u8]| {
            let (mut client, mut server) = UnixStream::pair().expect("local flight socket");
            client.write_all(bytes).expect("flight submission");
            client
                .shutdown(std::net::Shutdown::Write)
                .expect("frame EOF");
            read_closed_binding_flight_submission(&mut server, nonce)
        };
        assert_eq!(
            read(&frame, &[7; 16]).expect("exact Cache packet"),
            [9; CLOSED_CACHE_OWNER_READBACK_BYTES_V2]
        );
        assert!(read(&frame, &[8; 16]).is_err());
        let mut changed = frame;
        changed[0] ^= 1;
        assert!(read(&changed, &[7; 16]).is_err());
        assert!(read(&frame[..frame.len() - 1], &[7; 16]).is_err());
        assert!(read(&[frame.as_slice(), &[1]].concat(), &[7; 16]).is_err());
    }

    #[test]
    fn q04_replay_header_bypasses_only_the_unresolved_hold_gate() {
        let (mut client, mut server) = UnixStream::pair().expect("local policy socket");
        let mut request = [0_u8; REQUEST_BYTES];
        request[..8].copy_from_slice(POLICY_BINDING_REPLAY_QUERY_MAGIC_V5);
        request[8..24].copy_from_slice(&[1; 16]);
        client.write_all(&request).expect("Q04 replay request");

        let ordinary_gate_opened = Cell::new(false);
        let (_, mode) = read_head_request(&mut server, || {
            ordinary_gate_opened.set(true);
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "held Root CAS").into())
        })
        .expect("exact replay may inspect a held decision");
        assert!(matches!(mode, HeadRequestMode::ClosedBindingReplay));
        assert!(!ordinary_gate_opened.get());

        request[8..24].fill(0);
        let (mut client, mut server) = UnixStream::pair().expect("local policy socket");
        client
            .write_all(&request)
            .expect("zero nonce replay request");
        assert!(read_head_request(&mut server, || Ok(())).is_err());
    }

    #[test]
    fn root_effect_ack_headers_keep_the_held_gate_closed_for_other_modes() {
        for magic in [
            ROOT_EFFECT_ACK_QUERY_MAGIC_V1,
            ROOT_EFFECT_ACK_REPLAY_QUERY_MAGIC_V1,
        ] {
            let (mut client, mut server) = UnixStream::pair().expect("local Root ACK socket");
            let mut request = [0; REQUEST_BYTES];
            request[..8].copy_from_slice(magic);
            request[8..24].fill(7);
            client.write_all(&request).expect("Root ACK header");
            let gate_opened = Cell::new(false);
            let (_, mode) = read_head_request(&mut server, || {
                gate_opened.set(true);
                Err(io::Error::new(io::ErrorKind::PermissionDenied, "Root hold").into())
            })
            .expect("held Root ACK mode");
            assert!(!gate_opened.get());
            assert!(matches!(
                mode,
                HeadRequestMode::RootEffectAck | HeadRequestMode::RootEffectAckReplay
            ));

            request[8..24].fill(0);
            let (mut client, mut server) = UnixStream::pair().expect("local Root ACK socket");
            client.write_all(&request).expect("zero Root ACK nonce");
            assert!(read_head_request(&mut server, || Ok(())).is_err());
        }
    }

    #[test]
    fn root_effect_ack_submission_rejects_substitution_truncation_and_trailing_bytes() {
        let mut frame = [0; ROOT_EFFECT_ACK_SUBMIT_FRAME_BYTES_V1];
        frame[..8].copy_from_slice(ROOT_EFFECT_ACK_SUBMIT_MAGIC_V1);
        frame[8..24].fill(7);
        frame[24..].fill(9);
        let read = |bytes: &[u8], nonce| {
            let (mut client, mut server) = UnixStream::pair().expect("local ACK submission");
            client.write_all(bytes).expect("ACK bytes");
            client.shutdown(std::net::Shutdown::Write).expect("ACK EOF");
            server
                .set_read_timeout(Some(Duration::from_millis(20)))
                .unwrap();
            read_root_effect_ack_submission(&mut server, nonce)
        };
        assert_eq!(
            read(&frame, [7; 16]).unwrap(),
            vec![9; aos_sandbox::policy_compiler::CONTROLLER_EFFECT_ACK_READBACK_BYTES_V1]
        );
        assert!(read(&frame, [8; 16]).is_err());
        let mut changed = frame;
        changed[0] ^= 1;
        assert!(read(&changed, [7; 16]).is_err());
        assert!(read(&frame[..frame.len() - 1], [7; 16]).is_err());
        assert!(read(&[frame.as_slice(), &[1]].concat(), [7; 16]).is_err());
    }

    #[test]
    fn root_effect_ack_claim_requires_exact_binding_epoch_and_replay_eof() {
        let mut claim = [0; 40];
        claim[..32].fill(3);
        claim[32..].copy_from_slice(&4_u64.to_be_bytes());
        let read = |bytes: &[u8], replay| {
            let (mut client, mut server) = UnixStream::pair().expect("local ACK claim");
            client.write_all(bytes).expect("ACK claim bytes");
            client
                .shutdown(std::net::Shutdown::Write)
                .expect("claim EOF");
            read_root_effect_ack_claim(&mut server, replay)
        };
        assert_eq!(
            read(&claim, true).unwrap(),
            (ObjectDigest::from_bytes([3; 32]), 4)
        );
        assert!(read(&[claim.as_slice(), &[1]].concat(), true).is_err());
        assert!(read(&claim[..39], true).is_err());
        let mut empty = claim;
        empty[..32].fill(0);
        assert!(read(&empty, true).is_err());
        empty = claim;
        empty[32..].fill(0);
        assert!(read(&empty, true).is_err());
    }

    #[test]
    fn q04_stage_header_rejects_zero_nonce_before_root_custody() {
        let (mut client, mut server) = UnixStream::pair().expect("local policy socket");
        let mut request = [0_u8; REQUEST_BYTES];
        request[..8].copy_from_slice(POLICY_BINDING_STAGE_QUERY_MAGIC_V4);
        client.write_all(&request).expect("Q04 stage request");

        let root_custody_opened = Cell::new(false);
        assert!(
            read_head_request(&mut server, || {
                root_custody_opened.set(true);
                Ok(())
            })
            .is_err()
        );
        assert!(!root_custody_opened.get());
    }

    #[test]
    fn q04_stage_requires_exact_request_eof() {
        let (mut client, mut server) = UnixStream::pair().expect("local policy socket");
        client.write_all(&[1]).expect("trailing stage byte");
        assert!(require_q04_stage_request_end(&mut server).is_err());

        let (client, mut server) = UnixStream::pair().expect("local policy socket");
        client
            .shutdown(std::net::Shutdown::Write)
            .expect("stage EOF");
        assert!(require_q04_stage_request_end(&mut server).is_ok());
    }

    #[test]
    fn q04_preview_claim_requires_exact_staged_frame_and_eof() {
        let mut claim = [0_u8; CLOSED_BINDING_PREVIEW_CLAIM_BYTES];
        claim[..16].fill(1);
        claim[48..56].copy_from_slice(&1_u64.to_be_bytes());
        claim[56..64].copy_from_slice(&2_u64.to_be_bytes());
        claim[64..72].copy_from_slice(&3_u64.to_be_bytes());
        claim[72..88].fill(4);
        claim[88..96].copy_from_slice(&5_u64.to_be_bytes());
        claim[96..].fill(6);

        let (mut client, mut server) = UnixStream::pair().expect("local policy socket");
        client.write_all(&claim).expect("preview claim");
        client
            .shutdown(std::net::Shutdown::Write)
            .expect("preview EOF");
        let (staged, proposed) =
            read_closed_binding_preview_claim(&mut server).expect("exact staged preview frame");
        assert_eq!(staged.base().next_generation(), 1);
        assert_eq!(staged.issue_epoch(), 5);
        assert_eq!(proposed, [6; CLOSED_POLICY_BINDING_BYTES_V2]);

        let (mut client, mut server) = UnixStream::pair().expect("local policy socket");
        client.write_all(&claim).expect("preview claim");
        client.write_all(&[7]).expect("trailing byte");
        client
            .shutdown(std::net::Shutdown::Write)
            .expect("preview EOF");
        assert!(read_closed_binding_preview_claim(&mut server).is_err());

        claim[72..88].fill(0);
        let (mut client, mut server) = UnixStream::pair().expect("local policy socket");
        client.write_all(&claim).expect("zero challenge claim");
        client
            .shutdown(std::net::Shutdown::Write)
            .expect("preview EOF");
        assert!(read_closed_binding_preview_claim(&mut server).is_err());
    }

    #[test]
    fn unresolved_root_service_rejects_foreign_peer_and_new_queries() {
        let (_client, mut server) = UnixStream::pair().expect("replay-only socket");
        let uid = rustix::process::getuid().as_raw();
        let gid = rustix::process::getgid().as_raw();
        let error = serve_held_binding_request(&mut server, uid + 1, gid)
            .err()
            .expect("foreign peer");
        assert_eq!(
            error.downcast_ref::<io::Error>().map(io::Error::kind),
            Some(io::ErrorKind::PermissionDenied)
        );

        let (mut client, mut server) = UnixStream::pair().expect("replay-only socket");
        let mut request = [0_u8; REQUEST_BYTES];
        request[..8].copy_from_slice(POLICY_BINDING_STAGE_QUERY_MAGIC_V4);
        request[8..24].copy_from_slice(&[1; 16]);
        client.write_all(&request).expect("new Q04 stage query");
        assert!(serve_held_binding_request(&mut server, uid, gid).is_err());
    }

    #[test]
    fn read_only_and_cache_request_modes_reach_root_custody_gate() {
        for magic in [
            POLICY_HEAD_QUERY_MAGIC_V2,
            POLICY_HEAD_LEASE_QUERY_MAGIC_V3,
            POLICY_CACHE_READBACK_QUERY_MAGIC_V5,
            POLICY_CACHE_SIGNER_QUERY_MAGIC_V6,
            POLICY_BINDING_STAGE_QUERY_MAGIC_V4,
            POLICY_BINDING_PREVIEW_QUERY_MAGIC_V4,
        ] {
            let (mut client, mut server) = UnixStream::pair().expect("local policy socket");
            let mut request = [0_u8; REQUEST_BYTES];
            request[..8].copy_from_slice(magic);
            request[8..24].copy_from_slice(&[1; 16]);
            client.write_all(&request).expect("supported request");

            let root_custody_opened = Cell::new(false);
            assert!(
                read_head_request(&mut server, || {
                    root_custody_opened.set(true);
                    Ok(())
                })
                .is_ok()
            );
            assert!(root_custody_opened.get());
        }
    }

    struct ScriptedExchange {
        incoming: Cursor<Vec<u8>>,
        outgoing: Vec<u8>,
        fail_write: bool,
    }

    impl ScriptedExchange {
        fn new(incoming: Vec<u8>, fail_write: bool) -> Self {
            Self {
                incoming: Cursor::new(incoming),
                outgoing: Vec::new(),
                fail_write,
            }
        }
    }

    impl Read for ScriptedExchange {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.incoming.read(buffer)
        }
    }

    impl Write for ScriptedExchange {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            if self.fail_write {
                return Err(io::Error::from(io::ErrorKind::BrokenPipe));
            }
            self.outgoing.extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn lost_complete_or_terminal_ack_retains_root_hold() {
        let nonce = [9; 16];
        let binding = [10; 32];
        let epoch = 11_u64;
        let released = Cell::new(false);

        let mut lost_complete = ScriptedExchange::new(Vec::new(), true);
        assert!(
            complete_closed_binding_handoff_v4(&mut lost_complete, &nonce, &binding, epoch, || {
                released.set(true);
                Ok(())
            },)
            .is_err()
        );
        assert!(!released.get());

        let mut lost_terminal_ack = ScriptedExchange::new(Vec::new(), false);
        assert!(
            complete_closed_binding_handoff_v4(
                &mut lost_terminal_ack,
                &nonce,
                &binding,
                epoch,
                || {
                    released.set(true);
                    Ok(())
                },
            )
            .is_err()
        );
        assert_eq!(
            &lost_terminal_ack.outgoing[..8],
            POLICY_BINDING_COMPLETE_MAGIC_V4
        );
        assert!(!released.get());
    }

    #[test]
    fn exact_terminal_ack_releases_only_after_complete() {
        let nonce = [9; 16];
        let binding = [10; 32];
        let epoch = 11_u64;
        let mut terminal_ack = Vec::new();
        terminal_ack.extend_from_slice(POLICY_BINDING_TERMINAL_ACK_MAGIC_V4);
        terminal_ack.extend_from_slice(&nonce);
        terminal_ack.extend_from_slice(&binding);
        terminal_ack.extend_from_slice(&epoch.to_be_bytes());
        let released = Cell::new(false);

        let mut exchange = ScriptedExchange::new(terminal_ack.clone(), false);
        complete_closed_binding_handoff_v4(&mut exchange, &nonce, &binding, epoch, || {
            released.set(true);
            Ok(())
        })
        .expect("exact terminal acknowledgement");
        assert_eq!(&exchange.outgoing[..8], POLICY_BINDING_COMPLETE_MAGIC_V4);
        assert!(released.get());

        let mut trailing_ack = terminal_ack.clone();
        trailing_ack.push(1);
        let mut trailing = ScriptedExchange::new(trailing_ack, false);
        released.set(false);
        assert!(
            complete_closed_binding_handoff_v4(&mut trailing, &nonce, &binding, epoch, || {
                released.set(true);
                Ok(())
            },)
            .is_err()
        );
        assert!(!released.get());

        terminal_ack[..8].copy_from_slice(POLICY_BINDING_ACK_MAGIC_V4);
        let mut wrong_version = ScriptedExchange::new(terminal_ack, false);
        released.set(false);
        assert!(
            complete_closed_binding_handoff_v4(&mut wrong_version, &nonce, &binding, epoch, || {
                released.set(true);
                Ok(())
            },)
            .is_err()
        );
        assert!(!released.get());
    }

    #[test]
    fn offline_hold_selector_requires_one_exact_nonzero_digest() {
        let digest = ObjectDigest::from_bytes([0xab; 32]);
        let encoded = binding_head_hex(digest);
        assert_eq!(parse_binding_head(&encoded).expect("exact digest"), digest);
        assert!(parse_binding_head(&encoded[..63]).is_err());
        assert!(parse_binding_head(&"0".repeat(64)).is_err());
        assert!(parse_binding_head(&"g".repeat(64)).is_err());
    }

    #[test]
    fn lease_ack_is_nonce_and_version_bound() {
        let mut acknowledgement = [0_u8; 24];
        acknowledgement[..8].copy_from_slice(POLICY_HEAD_LEASE_ACK_MAGIC_V3);
        acknowledgement[8..].copy_from_slice(&[1; 16]);
        assert!(validate_lease_ack(&acknowledgement, &[1; 16]).is_ok());

        assert!(validate_lease_ack(&acknowledgement, &[2; 16]).is_err());
        acknowledgement[0] ^= 1;
        assert!(validate_lease_ack(&acknowledgement, &[1; 16]).is_err());
    }

    #[test]
    fn closed_binding_frames_reject_nonce_length_head_and_epoch_substitution() {
        let nonce = [1; 16];
        let head = [2; 32];
        let mut submission = [0_u8; CLOSED_BINDING_SUBMISSION_BYTES];
        submission[..8].copy_from_slice(POLICY_BINDING_SUBMIT_MAGIC_V4);
        submission[8..24].copy_from_slice(&nonce);
        submission[24..28].copy_from_slice(
            &u32::try_from(CLOSED_POLICY_BINDING_BYTES_V2)
                .unwrap()
                .to_be_bytes(),
        );
        assert_eq!(
            decode_closed_binding_submission(&submission, &nonce)
                .expect("exact frame")
                .len(),
            CLOSED_POLICY_BINDING_BYTES_V2
        );
        assert!(decode_closed_binding_submission(&submission, &[3; 16]).is_err());
        submission[24] ^= 1;
        assert!(decode_closed_binding_submission(&submission, &nonce).is_err());

        let mut acknowledgement = [0_u8; CLOSED_BINDING_ACK_BYTES];
        acknowledgement[..8].copy_from_slice(POLICY_BINDING_ACK_MAGIC_V4);
        acknowledgement[8..24].copy_from_slice(&nonce);
        acknowledgement[24..56].copy_from_slice(&head);
        acknowledgement[56..64].copy_from_slice(&4_u64.to_be_bytes());
        assert!(validate_closed_binding_ack(&acknowledgement, &nonce, &head, 4).is_ok());
        assert!(validate_closed_binding_ack(&acknowledgement, &[3; 16], &head, 4).is_err());
        assert!(validate_closed_binding_ack(&acknowledgement, &nonce, &[3; 32], 4).is_err());
        assert!(validate_closed_binding_ack(&acknowledgement, &nonce, &head, 5).is_err());
        acknowledgement[0] ^= 1;
        assert!(validate_closed_binding_ack(&acknowledgement, &nonce, &head, 4).is_err());
    }

    #[test]
    fn closed_cache_response_rejects_wrong_magic_and_client_session() {
        let client_nonce = [2; 16];
        let mut response = [0_u8; CLOSED_CACHE_READBACK_SUBMIT_FRAME_BYTES_V5];
        response[..8].copy_from_slice(POLICY_CACHE_READBACK_SUBMIT_MAGIC_V5);
        response[8..24].copy_from_slice(&client_nonce);
        assert_eq!(
            decode_cache_response(&response, &client_nonce)
                .expect("closed frame")
                .len(),
            CLOSED_CACHE_READBACK_SUBMIT_FRAME_BYTES_V5 - 24
        );
        assert!(decode_cache_response(&response, &[3; 16]).is_err());
        response[..8].copy_from_slice(POLICY_BINDING_SUBMIT_MAGIC_V4);
        assert!(decode_cache_response(&response, &client_nonce).is_err());
    }

    #[test]
    fn staged_cache_signer_submission_is_exactly_session_bound() {
        let client_nonce = [2; 16];
        let mut submission = [0; CLOSED_CACHE_SIGNER_SUBMIT_FRAME_BYTES_V6];
        submission[..8].copy_from_slice(POLICY_CACHE_SIGNER_SUBMIT_MAGIC_V6);
        submission[8..24].copy_from_slice(&client_nonce);
        submission[24..].fill(7);
        assert_eq!(
            decode_cache_signer_submission(&submission, &client_nonce)
                .expect("exact V2 submission"),
            [7; CLOSED_CACHE_OWNER_READBACK_BYTES_V2]
        );
        assert!(decode_cache_signer_submission(&submission, &[3; 16]).is_err());
        submission[..8].copy_from_slice(POLICY_CACHE_READBACK_SUBMIT_MAGIC_V5);
        assert!(decode_cache_signer_submission(&submission, &client_nonce).is_err());
    }

    #[test]
    fn explicit_project_credentials_require_an_exact_complete_pair() {
        let directory = tempfile::tempdir().expect("credential directory");
        assert!(
            read_optional_explicit_project(directory.path())
                .expect("absent pair")
                .is_none()
        );

        std::fs::write(directory.path().join("project-head-v2.packet"), [1; 328])
            .expect("project packet");
        assert!(read_optional_explicit_project(directory.path()).is_err());

        std::fs::write(directory.path().join("project-layer-v2.json"), b"input")
            .expect("project input");
        let (packet, input) = read_optional_explicit_project(directory.path())
            .expect("complete pair")
            .expect("configured pair");
        assert_eq!(packet.len(), EXPLICIT_PROJECT_PACKET_BYTES);
        assert_eq!(input, b"input");

        std::fs::write(directory.path().join("project-head-v2.packet"), [1; 327])
            .expect("short packet");
        assert!(read_optional_explicit_project(directory.path()).is_err());
    }

    #[test]
    fn project_source_modes_reject_missing_and_cross_version_credentials() {
        assert!(require_single_project_source(false, false).is_err());
        assert!(require_single_project_source(true, true).is_err());
        assert!(require_single_project_source(true, false).is_ok());
        assert!(require_single_project_source(false, true).is_ok());

        let legacy = Some((b"legacy-packet".as_slice(), b"legacy-input".as_slice()));
        let explicit = Some((b"explicit-packet".as_slice(), b"explicit-input".as_slice()));
        assert!(select_project_source(HeadRequestMode::Query, None, explicit).is_err());
        assert!(select_project_source(HeadRequestMode::Lease, None, explicit).is_err());
        assert!(select_project_source(HeadRequestMode::ClosedBinding, legacy, None).is_err());
        assert!(select_project_source(HeadRequestMode::ClosedCacheReadback, legacy, None).is_err());
        assert!(select_project_source(HeadRequestMode::StagedCacheSigner, legacy, None).is_err());
        assert_eq!(
            select_project_source(HeadRequestMode::ClosedBinding, None, explicit)
                .expect("explicit source")
                .0,
            b"explicit-packet"
        );
        assert_eq!(
            select_project_source(HeadRequestMode::ClosedCacheReadback, None, explicit)
                .expect("explicit source")
                .0,
            b"explicit-packet"
        );
        assert_eq!(
            select_project_source(HeadRequestMode::StagedCacheSigner, None, explicit)
                .expect("explicit source")
                .0,
            b"explicit-packet"
        );
    }
}

fn read_bounded(path: &Path, maximum: u64) -> io::Result<Vec<u8>> {
    let file = File::open(path)?;
    let mut bytes = Vec::new();
    file.take(maximum + 1).read_to_end(&mut bytes)?;
    if bytes.is_empty() || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "credential size",
        ));
    }
    Ok(bytes)
}

fn read_optional_cache_pin(root: &Path) -> io::Result<Option<Vec<u8>>> {
    read_optional_pin(root, "cache-owner-readback-public-key")
}

fn read_optional_pin(root: &Path, name: &str) -> io::Result<Option<Vec<u8>>> {
    match read_bounded(&root.join(name), 80) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn read_optional_explicit_project(root: &Path) -> io::Result<Option<(Vec<u8>, Vec<u8>)>> {
    read_optional_project(
        root,
        "project-head-v2.packet",
        EXPLICIT_PROJECT_PACKET_BYTES,
        "project-layer-v2.json",
    )
}

fn read_optional_project(
    root: &Path,
    packet_name: &str,
    packet_bytes: usize,
    input_name: &str,
) -> io::Result<Option<(Vec<u8>, Vec<u8>)>> {
    let packet = read_bounded(&root.join(packet_name), packet_bytes as u64);
    let input = read_bounded(&root.join(input_name), 3 * 1024);
    match (packet, input) {
        (Ok(packet), Ok(input)) if packet.len() == packet_bytes => Ok(Some((packet, input))),
        (Err(packet), Err(input))
            if packet.kind() == io::ErrorKind::NotFound
                && input.kind() == io::ErrorKind::NotFound =>
        {
            Ok(None)
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "project packet and input credentials must be provisioned together",
        )),
    }
}
