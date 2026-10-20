//! Admits externally signed deployment policy inputs under root-owned custody.
//!
//! This service commits the monotonic deployment input head and serves an
//! authenticated signed-head receipt to the node controller. Historical
//! exchanges retain exact protected decision and terminal readback.
//! Separate Cache diagnostic exchanges do not admit the project source against
//! the Controller publisher journal or authorize compiler publication or effects.
//! Root-only recovery modes inspect or release an abandoned version-4 hold.
//! A separate credential-independent V7 listener answers historical Cache
//! packet recovery only for the authenticated Controller peer.
//! `AOSPHQ4V` performs an inert staged Root-last comparison. Both forms of
//! `AOSPHQ04` and the retired V4/V7/V8 signer-flight profiles are refused before
//! Root custody. Historical Q04/V7/V8 replay remains available with its exact
//! claims and held-owner checks. Current Create uses the separate original-Q04
//! route and its actual receiving, currentness and owner-disposal gates.
//! A distinct V8 ACK exchange records Controller's signed no-Apply receipt
//! against the still-held AOSPCP02 CAS; it cannot release any owner. The V8
//! terminal exchange keeps Root's writer across Controller's durable receipt
//! and Root's verified AOSPC88T row.
//! `--show-controller-hold` inspects the protected Controller record;
//! `--release-controller-hold` checks exact root custody under the fixed
//! Controller-then-root lock order before unfreezing the Controller journal.
//! `--release-source-domain-hold` retains Controller and source-domain writers
//! in that order before exact root cold readback; it must precede Controller
//! release when both journals are held.
//! `AOSSGQ01` separately opens the genuine local-Root Source genesis writer
//! last, under independently pinned Controller/Source readbacks. Its original
//! stream remains held through all durable floor/ACK joins. Raw reply records
//! cannot mint the separately qualified live Root client proof.

use aos_sandbox_policy::controller_project_readback::CONTROLLER_PROJECT_ADMISSION_READBACK_BYTES_V1;

use aos_sandbox_protocol::source_genesis_wire::{
    ROOT_SOURCE_GENESIS_QUERY_MAGIC_V1,
};

use aos_sandbox_protocol::source_genesis_wire as genesis_wire;

use aos_sandbox_policy::signed_inputs::{
    PolicyDeploymentInputsV1, verify_signed_project_policy_source_v2,
};

use aos_sandbox_broker::root_settlement::{
    ROOT_V8_SETTLED_QUERY_MAGIC, encode_root_v8_settled_reply_v1,
};

#[path = "aos-sandbox-policy-authorityd/startup_credentials.rs"]
mod startup_credentials;

use aos_sandbox::normal_root::RootStartupCredentialMemberV1 as CredentialMember;
use startup_credentials::RootStartupCredentialReads;

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

use aos_sandbox_protocol::cache_owner_readback::{
    CLOSED_CACHE_OWNER_READBACK_BYTES_V2,
    PinnedCacheOwnerReadbackSignerV1,
};
use aos_sandbox::journal::{
    SOURCE_PROJECT_ADMISSION_CHALLENGE_BYTES_V1,
    SOURCE_PROJECT_ADMISSION_RESERVATION_BYTES_V1,
    SourceProjectAdmissionChallengeV1,
    SourceProjectAdmissionReservationV1,
};
use aos_sandbox::source_domain::ProtectedSourceDomainJournalOwnerV1;
use aos_sandbox::policy_compiler::{
    CLOSED_POLICY_BINDING_BYTES_V2, CONTROLLER_PROJECT_DISPATCH_READBACK_BYTES_V1, CONTROLLER_PROJECT_TERMINAL_READBACK_BYTES_V1,
    CacheSignerRootChallengeStatusV2, CacheSignerRootSettlementStateV2,
    ClosedPolicyBindingDecisionV2, ClosedPolicyRootCasBaseV2,
    ControllerEffectAckChallengeV1, PinnedSourceHoldReadbackSignerV1,
    ROOT_PROJECT_ADMISSION_ABORT_QUERY_MAGIC, ROOT_PROJECT_ADMISSION_COMMIT_QUERY_MAGIC,
    ROOT_PROJECT_ADMISSION_CURRENT_QUERY_MAGIC, ROOT_PROJECT_ADMISSION_INTENT_QUERY_MAGIC,
    ROOT_PROJECT_ADMISSION_INTENT_REPLAY_MAGIC, ROOT_PROJECT_ADMISSION_OUTCOME_QUERY_MAGIC,
    ROOT_PROJECT_ADMISSION_STAGE_QUERY_MAGIC, ROOT_PROJECT_HISTORY_FLOOR_QUERY_MAGIC,
    ROOT_PROJECT_HISTORY_RETIRE_MAGIC, ROOT_PROJECT_NEGATIVE_INTENT_QUERY_MAGIC,
    ROOT_PROJECT_RESERVATION_CANCEL_MAGIC, ROOT_PROJECT_RESERVATION_CANCEL_QUERY_MAGIC, RootPolicyStartupDeploymentV1, RootPolicyStartupJournalV1,
    RootV8HeldTerminalStepV1, SourceHoldReadbackChallengeV1, StagedClosedPolicyRootBaseV2,
    abandon_fixed_cache_signer_challenge_v2, abort_fixed_root_project_admission_v1,
    acknowledge_and_verify_fixed_closed_root_v8_terminal_v1,
    acknowledge_fixed_closed_root_v8_effect_v1,
    acknowledge_verify_and_release_fixed_closed_root_v8_terminal_v1,
    admit_fixed_cache_readback_pin_v1, admit_fixed_controller_hold_pin_v1,
    admit_fixed_policy_deployment_head_v1, admit_fixed_policy_signer_pins_v1,
    admit_fixed_root_project_source_from_owner_proofs_v1, admit_fixed_source_hold_pin_v1,
    cancel_fixed_root_project_reservation_v1, compact_fixed_cache_signer_root_journal_v2,
    encode_root_current_project_admission_stage_reply_v1,
    encode_root_project_admission_outcome_reply_v1, encode_root_project_admission_stage_reply_v1,
    encode_root_project_admission_terminal_reply_v1, encode_root_project_history_floor_reply_v1,
    encode_root_project_intent_replay_reply_v1, encode_root_project_intent_reply_v1,
    encode_root_project_negative_intent_reply_v1, encode_root_project_reservation_cancel_reply_v1,
    fixed_root_project_admission_recovery_required_v1,
    fixed_root_project_history_readback_available_v1,
    fixed_root_project_negative_recovery_available_v1,
    fixed_root_source_genesis_recovery_available_v1,
    prepare_fixed_root_project_admission_intent_v1, prepare_fixed_root_project_negative_intent_v1,
    read_fixed_cache_signer_challenge_v2, read_fixed_inert_closed_policy_binding_hold_v1,
    read_fixed_policy_cache_hold_v1, record_fixed_cache_signer_root_settlement_v2,
    recover_fixed_cache_signer_abandonment_v2, recover_fixed_cache_signer_root_history_v2,
    recover_fixed_cache_signer_root_settlement_v2, recover_fixed_closed_policy_binding_decision_v2,
    recover_fixed_closed_root_v8_effect_ack_v1,
    recover_fixed_closed_root_v8_predecessor_settlement_v1,
    recover_fixed_closed_root_v8_terminal_custody_v1,
    recover_fixed_closed_root_v8_verified_terminal_v1,
    recover_fixed_committed_source_held_binding_v2,
    recover_fixed_root_current_project_admission_stage_v1,
    recover_fixed_root_project_admission_intent_v1,
    recover_fixed_root_project_admission_outcome_v1, recover_fixed_root_project_admission_stage_v1,
    recover_fixed_root_project_history_floor_v1,
    recover_fixed_root_project_reservation_cancellation_v1,
    recover_fixed_root_project_source_pin_v1, recover_fixed_root_unstaged_project_intent_v1,
    release_fixed_closed_policy_controller_hold_v1,
    release_fixed_closed_policy_source_domain_hold_v1,
    release_fixed_inert_closed_policy_binding_hold_v1,
    require_no_fixed_closed_policy_binding_hold_v1, retire_fixed_root_project_history_v1,
    stage_fixed_cache_signer_challenge_v2, stage_fixed_root_project_admission_v1,
    verify_fixed_policy_cache_owner_readback_v2,
    with_fixed_explicit_closed_policy_binding_session_v2,
};
use aos_sandbox::{Journal, journal::controller::production_journal_limits};
use aos_sandbox_services::cache_signer_exchange::begin_root_cache_signer_exchange_v2;
use aos_sandbox_services::policy_authority_client::{
    POLICY_AUTHORITY_SOCKET_PATH_V2, POLICY_BINDING_PREVIEW_QUERY_MAGIC_V4,
    POLICY_BINDING_PREVIEW_REPLY_MAGIC_V4, POLICY_BINDING_QUERY_MAGIC_V4,
    POLICY_BINDING_RECEIPT_MAGIC_V4, POLICY_BINDING_REPLAY_QUERY_MAGIC_V5,
    POLICY_BINDING_REPLAY_REPLY_MAGIC_V5,
    POLICY_BINDING_SOURCE_FLIGHT_REPLAY_QUERY_MAGIC_V7,
    POLICY_BINDING_SOURCE_FLIGHT_REPLAY_QUERY_MAGIC_V8,
    POLICY_BINDING_SOURCE_FLIGHT_REPLAY_REPLY_MAGIC_V7,
    POLICY_BINDING_SOURCE_FLIGHT_REPLAY_REPLY_MAGIC_V8,
    POLICY_BINDING_STAGE_QUERY_MAGIC_V4, POLICY_BINDING_STAGE_REPLY_MAGIC_V4,
};
use aos_sandbox_services::policy_cache_readback_client::{
    CLOSED_CACHE_SIGNER_RECOVERY_FRAME_BYTES_V7, CLOSED_CACHE_SIGNER_SUBMIT_FRAME_BYTES_V6,
    CacheSignerRootRecoveryV7,
    POLICY_CACHE_SIGNER_CHALLENGE_MAGIC_V6, POLICY_CACHE_SIGNER_QUERY_MAGIC_V6,
    POLICY_CACHE_SIGNER_RECOVERY_QUERY_MAGIC_V7, POLICY_CACHE_SIGNER_RECOVERY_SOCKET_PATH_V7,
    POLICY_CACHE_SIGNER_SETTLED_MAGIC_V6, POLICY_CACHE_SIGNER_SUBMIT_MAGIC_V6,
    decode_cache_signer_recovery_submission_v7, encode_cache_signer_recovery_observation_v7,
};
use aos_sandbox_services::policy_root_ack_v8_client::{
    ROOT_V8_ACK_CHALLENGE_FRAME_BYTES, ROOT_V8_ACK_CHALLENGE_MAGIC, ROOT_V8_ACK_QUERY_MAGIC,
    ROOT_V8_ACK_REPLAY_QUERY_MAGIC, ROOT_V8_ACK_SUBMIT_FRAME_BYTES, ROOT_V8_ACK_SUBMIT_MAGIC,
    ROOT_V8_RELEASE_CHALLENGE_MAGIC, ROOT_V8_RELEASE_QUERY_MAGIC,
    ROOT_V8_RELEASE_REPLAY_QUERY_MAGIC, ROOT_V8_RELEASE_SUBMIT_FRAME_BYTES,
    ROOT_V8_RELEASE_SUBMIT_MAGIC, ROOT_V8_TERMINAL_ACK_CHALLENGE_MAGIC,
    ROOT_V8_TERMINAL_ACK_SUBMIT_MAGIC, ROOT_V8_TERMINAL_QUERY_MAGIC,
    ROOT_V8_TERMINAL_RECEIPT_CHALLENGE_MAGIC, ROOT_V8_TERMINAL_RECEIPT_SUBMIT_FRAME_BYTES,
    ROOT_V8_TERMINAL_RECEIPT_SUBMIT_MAGIC, ROOT_V8_TERMINAL_REPLAY_QUERY_MAGIC,
    encode_root_v8_ack_reply, encode_root_v8_release_reply, encode_root_v8_release_stage,
    encode_root_v8_terminal_reply, encode_root_v8_terminal_stage_ack,
};
use aos_sandbox_policy::policy_signer_credential::{PinnedPolicySignerV1, PolicySignerRoleV1};
use aos_sandbox_services::source_genesis_flight::{
    RootFirstSourceSuccessorAttemptV2, RootFirstSourceSuccessorRouteV2, RootProjectGenesisAttemptV3,
    RootGlobalGenesisAttemptV2,
    RootProjectSuccessorAttemptV3,
    serve_root_source_genesis_flight_v1, serve_root_source_genesis_recovery_v1,
};
use aos_sandbox_services::source_signer_exchange::{
    request_root_source_project_admission_readback_v1,
    request_root_source_project_reservation_readback_v1,
    request_root_source_project_retirement_readback_v1,
};
use aos_sandbox_core::ObjectDigest;
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
const CLOSED_BINDING_REPLAY_CLAIM_BYTES: usize = 32 + 8;
const CLOSED_BINDING_PREVIEW_CLAIM_BYTES: usize = 96 + CLOSED_POLICY_BINDING_BYTES_V2;
const CACHE_SIGNER_RPC_TIMEOUT: Duration = Duration::from_secs(75);

#[derive(Clone, Copy)]
enum HeadRequestMode {
    GitEvidenceView,
    GitCoverageEnrollment,
    SourceGenesis,
    SourceResourceGlobalGenesis,
    SourceFirstSuccessor,
    SourceProjectGenesis,
    SourceProjectSuccessor,
    CreateQ04,
    ConsumerReadPreRoot,
    ClosedBinding,
    ClosedBindingReplay,
    RootV8EffectAck,
    RootV8EffectAckReplay,
    RootV8Terminal,
    RootV8TerminalReplay,
    RootV8TerminalRelease,
    RootV8TerminalReleaseReplay,
    RootV8SettledGrant,
    ProjectAdmissionOutcomeReplay,
    ProjectAdmissionIntent,
    ProjectNegativeIntent,
    ProjectAdmissionIntentReplay,
    ProjectAdmissionStage,
    ProjectAdmissionCommit,
    ProjectAdmissionAbort,
    ProjectAdmissionCurrentStage,
    ProjectReservationCancel,
    ProjectReservationCancelReplay,
    ProjectHistoryFloorReplay,
    ProjectHistoryRetirement,
    ClosedBindingStage,
    ClosedBindingPreview,
    ClosedBindingSourceTerminalReplay,
    ClosedBindingSourceCasReplay,
    StagedCacheSigner,
}

struct CurrentRootCredentials {
    packet: Vec<u8>,
    node: Vec<u8>,
    site: Vec<u8>,
    backend: Vec<u8>,
    catalogs: Vec<u8>,
    deployment_signer: PinnedPolicySignerV1,
    project_signer: PinnedPolicySignerV1,
    explicit_project: Option<(Vec<u8>, Vec<u8>)>,
    cache_pin: Option<Vec<u8>>,
    controller_hold_pin: Option<Vec<u8>>,
    source_hold_pin: Option<Vec<u8>>,
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
    // Capture every inherited descriptor before credentials/journals/listeners
    // or readback threads open anything. This is independent of method46 mode.
    let mut initial = aos_sandbox::normal_root::ProductionNormalRootInitialStartupV1::new();
    if let Err(cause) = initial.capture_once() {
        eprintln!("aos-sandbox-policy-authorityd: {cause}");
        // Intentional termination retains the same failed original owner.
        // No local Drop, recovery, receiving, refund or rearm follows.
        std::process::exit(1);
    }
    let Some(startup) = initial.take_capture() else {
        eprintln!("aos-sandbox-policy-authorityd: incomplete initial Root handoff");
        std::process::exit(1);
    };
    drop(initial);
    let startup = startup?;
    if rustix::process::geteuid().as_raw() != 0 || rustix::process::getuid().as_raw() != 0 {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "root required").into());
    }

    let mut arguments = std::env::args();
    let _program = arguments.next();
    let first = arguments
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "controller UID required"))?;
    if first.starts_with("--") {
        startup.require_non_normal_invocation()?;
        require_absent_git_evidence_credential()?;
    }
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
    let cache_signer_gid: u32 = arguments
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Cache signer GID required"))?
        .parse()?;
    if controller_uid == 0 || controller_gid == 0
        || (cache_signer_uid == 0) != (cache_signer_gid == 0)
        || arguments.next().is_some()
    {
        return Err(
            io::Error::new(io::ErrorKind::InvalidInput, "invalid controller identity").into(),
        );
    }

    let startup = startup.admit_normal([
        controller_uid,
        controller_gid,
        cache_signer_uid,
        source_signer_uid,
    ])?;
    if let Some(original) = startup.as_ref() {
        if original.cache_signer_gid() != cache_signer_gid {
            return Err(aos_sandbox::normal_root::NormalRootStartupErrorV1::Profile.into());
        }
    }
    if startup.is_none() {
        require_absent_git_evidence_credential()?;
    }

    // Only genuine normal startup consolidates these admissions under one
    // writer. The retained opening is custody, not paid receiving or activation.
    let resource_root_receiving = startup.as_ref()
        .is_some_and(|original| original.is_resource_receiving());
    let mut startup_journal = startup.as_ref().map(|_| RootPolicyStartupJournalV1::new());
    let binding_hold = match startup_journal.as_mut() {
        Some(journal) => {
            let Some(original) = startup.as_ref() else {
                return Err(io::Error::other("incomplete original Root startup handoff").into());
            };
            if let Err(cause) = original.open_policy_startup_journal_once(journal) {
                eprintln!("aos-sandbox-policy-authorityd: {cause}");
                if let Some(cause) = journal.failure() {
                    eprintln!("aos-sandbox-policy-authorityd: {cause}");
                }
                // Keep the same Root payer, partial journal and independent
                // posts resident. No credential/recovery/retry path follows.
                std::process::exit(1);
            }
            journal.read_binding_hold()
        }
        None => read_fixed_inert_closed_policy_binding_hold_v1(),
    };
    let binding_hold = match binding_hold {
        Ok(hold) => hold,
        Err(error) => {
            // Even failed opening gets a post disposition before its reached
            // originals are disposed. This does not establish Drained/refund.
            let post = finish_startup_journal_names(&mut startup_journal);
            if resource_root_receiving {
                let original_post = startup.as_ref().map(|original| original.recheck());
                eprintln!("aos-sandbox-policy-authorityd: binding hold: {error}");
                if let Err(later) = &post {
                    eprintln!("aos-sandbox-policy-authorityd: binding native post: {later}");
                }
                if let Some(Err(later)) = &original_post {
                    eprintln!("aos-sandbox-policy-authorityd: original Root post: {later}");
                }
                // The actual error, both independent posts, original payer and
                // same startup writer stay resident through process death.
                std::process::exit(1);
            }
            if let Some(journal) = startup_journal.take() {
                if journal.failure().is_some() {
                    // No recovery path follows this error. Keep the posted
                    // native reservoir through main's original diagnostic;
                    // error disposal ends custody before ordinary process exit.
                    return Err(journal.into_failure().into());
                }
                drop(journal);
            }
            post?;
            return Err(error.into());
        }
    };

    // An unresolved CAS never reaches credential admission. Its isolated
    // service admits only historical replay and the qualified, nonauthorizing
    // Controller ACK exchange; Root validates the pinned signer before writing.
    if binding_hold.is_some() {
        if resource_root_receiving {
            let missing = io::Error::new(io::ErrorKind::Unsupported,
                "historical binding recovery has no Root receiving supplier");
            let post = finish_startup_journal_names(&mut startup_journal);
            let original_post = startup.as_ref().map(|original| original.recheck());
            eprintln!("aos-sandbox-policy-authorityd: {missing}");
            if let Err(later) = &post {
                eprintln!("aos-sandbox-policy-authorityd: binding native post: {later}");
            }
            if let Some(Err(later)) = &original_post {
                eprintln!("aos-sandbox-policy-authorityd: original Root post: {later}");
            }
            // Do not enter unpriced historical probes or serving. The actual
            // held binding, writer and both post Results are still owned here.
            std::process::exit(1);
        }
        let post = finish_startup_journal_names(&mut startup_journal);
        drop(startup_journal);
        post?;
        require_absent_git_evidence_credential()?;
        return serve_held_binding_recovery(controller_uid, controller_gid, startup);
    }

    // Keep raw native originals and partial results in this main scope through
    // policy classification, independent posts and any exact recovery route.
    let mut credential_reads = RootStartupCredentialReads::default();
    let mut credential_loan = match (startup.as_ref(), startup_journal.as_mut()) {
        (Some(original), Some(journal)) => {
            match original.borrow_startup_credentials_once(journal) {
                Ok(loan) => Some(loan),
                Err(cause) => {
                    eprintln!("aos-sandbox-policy-authorityd: {cause}");
                    // Failed original RootR preparation stays resident; no
                    // credential read or historical recovery follows this debt.
                    std::process::exit(1);
                }
            }
        }
        _ => None,
    };
    let current = (|| -> Result<CurrentRootCredentials, Box<dyn Error>> {
        let key_bytes = credential_reads.read(credential_loan.as_ref(), CredentialMember::DeploymentKey)?;
        let deployment_signer =
            PinnedPolicySignerV1::decode(PolicySignerRoleV1::Deployment, &key_bytes)?;
        let packet = credential_reads.read(credential_loan.as_ref(), CredentialMember::DeploymentHead)?;
        let node = credential_reads.read(credential_loan.as_ref(), CredentialMember::Node)?;
        let site = credential_reads.read(credential_loan.as_ref(), CredentialMember::Site)?;
        let backend = credential_reads.read(credential_loan.as_ref(), CredentialMember::Backend)?;
        let catalogs = credential_reads.read(credential_loan.as_ref(), CredentialMember::Catalogs)?;
        let project_key_bytes = credential_reads.read(credential_loan.as_ref(), CredentialMember::ProjectKey)?;
        let project_signer =
            PinnedPolicySignerV1::decode(PolicySignerRoleV1::Project, &project_key_bytes)?;
        credential_reads.require_no_retired(credential_loan.as_ref())?;
        let explicit_project = credential_reads.explicit_project(credential_loan.as_ref())?;
        require_explicit_project_source(explicit_project.is_some())?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
        let now_unix_seconds = i64::try_from(now.as_secs())?;

        let inputs = PolicyDeploymentInputsV1 {
            node: &node,
            site: &site,
            backend: &backend,
            catalogs: &catalogs,
        };
        let deployment = RootPolicyStartupDeploymentV1::verify(
            &packet,
            &inputs,
            deployment_signer.verifying_key(),
            deployment_signer.generation(),
            now_unix_seconds,
        )?;
        if let Some((project_packet_v2, project_input_v2)) = explicit_project.as_ref() {
            let verified = verify_signed_project_policy_source_v2(
                project_packet_v2,
                project_input_v2,
                project_signer.verifying_key(),
                now_unix_seconds,
            )
            .map_err(aos_sandbox::policy_compiler::PolicyDeploymentHeadErrorV1::from)?;
            if verified.head().prerequisite_claims()[1] != deployment.head().packet_digest()
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
        let _legacy_sources = match credential_loan.as_mut().map(|loan| loan.journal_mut()).transpose()? {
            Some(mut journal) => {
                journal.admit_signer_pins(
                    deployment_signer.generation(),
                    deployment_signer.verifying_key(),
                    project_signer.generation(),
                    project_signer.verifying_key(),
                )?;
                journal.admit_deployment_head(deployment)?;
                None
            }
            None => {
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
                Some(deployment.into_sources())
            }
        };
        let cache_pin = credential_reads.optional(credential_loan.as_ref(), CredentialMember::CachePin)?;
        match credential_loan.as_mut().map(|loan| loan.journal_mut()).transpose()? {
            Some(mut journal) => journal.admit_cache_pin(cache_pin.as_deref())?,
            None => admit_fixed_cache_readback_pin_v1(
                cache_pin.as_deref(),
                deployment_signer.generation(),
                deployment_signer.verifying_key(),
                project_signer.generation(),
                project_signer.verifying_key(),
            )?,
        }
        let controller_hold_pin = credential_reads.optional(credential_loan.as_ref(), CredentialMember::ControllerPin)?;
        match credential_loan.as_mut().map(|loan| loan.journal_mut()).transpose()? {
            Some(mut journal) => journal.admit_controller_pin(controller_hold_pin.as_deref())?,
            None => admit_fixed_controller_hold_pin_v1(
                controller_hold_pin.as_deref(),
                deployment_signer.generation(),
                deployment_signer.verifying_key(),
                project_signer.generation(),
                project_signer.verifying_key(),
            )?,
        }
        let source_hold_pin = credential_reads.optional(credential_loan.as_ref(), CredentialMember::SourcePin)?;
        match credential_loan.as_mut().map(|loan| loan.journal_mut()).transpose()? {
            Some(mut journal) => journal.admit_source_pin(source_hold_pin.as_deref())?,
            None => admit_fixed_source_hold_pin_v1(
                source_hold_pin.as_deref(),
                deployment_signer.generation(),
                deployment_signer.verifying_key(),
                project_signer.generation(),
                project_signer.verifying_key(),
            )?,
        }

        Ok(CurrentRootCredentials {
            packet,
            node,
            site,
            backend,
            catalogs,
            deployment_signer,
            project_signer,
            explicit_project,
            cache_pin,
            controller_hold_pin,
            source_hold_pin,
        })
    })();
    // This disposition DATA comes from the actual still-borrowed original;
    // it creates no grant or successful credential result.
    if current.is_err() {
        if let Some(loan) = &credential_loan { loan.refuse_primary_v1(); }
    }
    let resource_credential_receiving = credential_loan.as_ref()
        .is_some_and(|loan| loan.is_resource_receiving());
    // Consume the entire borrowing Option before using the writer again. Each
    // present loan runs its actual finish and Drop fence; only owned post DATA
    // crosses into fallback and credential classification below.
    let credential_post = credential_loan.map(|loan| {
        loan.finish_once()
            .map_err(|cause| Box::new(cause) as Box<dyn Error>)
    });
    let post: Result<(), Box<dyn Error>> = match credential_post {
        Some(post) => post,
        None => finish_startup_journal_names(&mut startup_journal),
    };
    if let Err(error) = post {
        if resource_credential_receiving {
            // An earlier credential/read/verification failure stays the first
            // cause. The later native post is separate debt; neither Result,
            // raw reader, actual writer nor genuine Root owner is disposed.
            if let Err(first) = &current {
                eprintln!("aos-sandbox-policy-authorityd: {first}");
            }
            if let Some((name, cause)) = credential_reads.failure() {
                eprintln!("aos-sandbox-policy-authorityd: {name}: {cause}");
            }
            eprintln!("aos-sandbox-policy-authorityd: startup native post: {error}");
            if let Some(cause) = startup_journal.as_ref().and_then(|journal| journal.failure()) {
                eprintln!("aos-sandbox-policy-authorityd: {cause}");
            }
            std::process::exit(1);
        }
        // Ordinary startup keeps its existing post classification/disposition.
        // A replaced or unhealthy writer never enters either listener. The
        // original credential result is still resident at this classification.
        if let Some((name, cause)) = credential_reads.failure() {
            eprintln!("aos-sandbox-policy-authorityd: {name}: {cause}");
        }
        // Keep the original ordinary-path diagnostic as well as every retained
        // native Result; the receiving post may additionally fail containment.
        let error = startup_journal.as_ref().and_then(|journal| journal.failure())
            .map(|cause| Box::new(io::Error::other(cause.to_string())) as Box<dyn Error>)
            .unwrap_or(error);
        drop(startup_journal);
        return Err(error);
    }
    let current = match current {
        Ok(current) => {
            drop(startup_journal);
            current
        }
        Err(error) => {
            if resource_credential_receiving {
                eprintln!("aos-sandbox-policy-authorityd: current credentials: {error}");
                if let Some((name, cause)) = credential_reads.failure() {
                    eprintln!("aos-sandbox-policy-authorityd: {name}: {cause}");
                }
                // Independent credential/native posts completed above. Keep
                // their original writer and the earlier raw/current failure;
                // historical probes and serving need a separate receiving stage.
                std::process::exit(1);
            }
            // Fixed recovery probes reopen authority.journal. End the startup
            // flock after its post and error classification, before any probe.
            drop(startup_journal);
            require_absent_git_evidence_credential()?;
            if fixed_root_project_admission_recovery_required_v1()?
                || fixed_root_project_history_readback_available_v1()?
                || fixed_root_project_negative_recovery_available_v1()?
                || fixed_root_source_genesis_recovery_available_v1()?
            {
                eprintln!(
                    "aos-sandbox-policy-authorityd: current credentials unavailable; serving only exact retained recovery: {error}"
                );
                recover_fixed_root_unstaged_project_intent_v1()?;
                return serve_project_admission_recovery_only(
                    controller_uid,
                    controller_gid,
                    source_signer_uid,
                    startup.as_ref(),
                );
            }
            return Err(error);
        }
    };
    let CurrentRootCredentials {
        packet,
        node,
        site,
        backend,
        catalogs,
        deployment_signer,
        project_signer,
        explicit_project,
        cache_pin,
        controller_hold_pin,
        source_hold_pin,
    } = current;
    let inputs = PolicyDeploymentInputsV1 {
        node: &node,
        site: &site,
        backend: &backend,
        catalogs: &catalogs,
    };

    recover_fixed_root_unstaged_project_intent_v1()?;

    // The existing deployment admission above is sequencing, not a fabricated
    // current-policy token. Only the actual normal owner plus its independent
    // protected administrative credential can install dedicated Git evidence.
    if let Some(owner) = &startup {
        let mut attempt = owner.git_evidence_provisioning_attempt();
        if let Err(error) = attempt.install_once() {
            // Keep the original attempt and Root owner resident until OS
            // process death. This is not Drop, queue settlement or Drained.
            // An ambiguous append never continues into this listener loop.
            eprintln!("aos-sandbox-policy-authorityd: {error}");
            std::process::exit(1);
        }
        // Verified or absent installation data grant no Git route. Release
        // this dedicated writer before future evidence consumers can open it.
    }

    let head_service = CurrentRootHeadServiceV1 {
        startup: startup.as_ref(), controller_uid, controller_gid,
        cache_signer_uid, source_signer_uid, packet: &packet, inputs: &inputs,
        verifying_key: deployment_signer.verifying_key(),
        deployment_signer_generation: deployment_signer.generation(),
        explicit_project: explicit_project.as_ref()
            .map(|(packet, input)| (packet.as_slice(), input.as_slice())),
        project_key: project_signer.verifying_key(),
        project_signer_generation: project_signer.generation(),
        cache_pin: cache_pin.as_deref(), source_pin: source_hold_pin.as_deref(),
        controller_hold_pin: controller_hold_pin.as_deref(),
    };
    let current_policy_inputs = aos_sandbox::policy_compiler::RootCurrentPolicyInputDataV1::new(
        &packet,
        &inputs,
        explicit_project.as_ref().map(|(packet, input)| (packet.as_slice(), input.as_slice())),
    );
    if let Some(mut listener) = startup.as_ref()
        .and_then(|owner| owner.policy_authority_listener_receiving())
    {
        if let Err(cause) = listener.bind_once() {
            let first = listener.failure().map(ToString::to_string)
                .unwrap_or_else(|| cause.to_string());
            eprintln!("aos-sandbox-policy-authorityd: {first}");
            std::process::exit(1);
        }
        loop {
            let mut flight = match listener.next_flight() {
                Ok(flight) => flight,
                Err(cause) => {
                    eprintln!("aos-sandbox-policy-authorityd: {cause}");
                    std::process::exit(1);
                }
            };
            if flight.accept_once().is_err() {
                if let Some(cause) = flight.failure() {
                    eprintln!("aos-sandbox-policy-authorityd: {cause}");
                }
                std::process::exit(1);
            }
            let Some(stream) = flight.take_dispatch_original_once() else {
                std::process::exit(1);
            };
            let private = aos_sandbox_broker_session_security::controller_composition::
                original_create_storage_use_security_shape_v1()
                .ok_or("actual Create Storage security layout is unavailable")?;
            let mut prelude = aos_sandbox::policy_compiler::RootPolicyPreludeOriginalV1::new(
                stream, &mut flight,
            );
            if prelude.receive_prefix_once_v1().is_err() {
                let _owed = prelude.finish_negative_once_v1();
                if let Some(cause) = prelude.failure() {
                    eprintln!("aos-sandbox-policy-authorityd: {cause}");
                }
                std::process::exit(1);
            }
            if prelude.purpose_v1() == Some(aos_sandbox::policy_compiler::RootPolicyPurposeV1::ExecutionNoApply) {
                if let Err(cause) = prelude.serve_execution_no_apply_once_v2(&current_policy_inputs) {
                    eprintln!("aos-sandbox-policy-authorityd: Execution NoApply disposition: {cause}");
                    if let Some(cause) = flight.failure() {
                        eprintln!("aos-sandbox-policy-authorityd: {cause}");
                    }
                    std::process::exit(1);
                }
                continue;
            }
            if prelude.purpose_v1() == Some(aos_sandbox::policy_compiler::RootPolicyPurposeV1::Delete) {
                if let Err(cause) = prelude.serve_delete_once_v4(&current_policy_inputs) {
                    eprintln!("aos-sandbox-policy-authorityd: Delete terminal disposition: {cause}");
                    if let Some(cause) = flight.failure() {
                        eprintln!("aos-sandbox-policy-authorityd: {cause}");
                    }
                    std::process::exit(1);
                }
                continue;
            }
            if prelude.purpose_v1() == Some(aos_sandbox::policy_compiler::RootPolicyPurposeV1::StopCleanup) {
                if let Err(cause) = prelude.serve_stop_cleanup_once_v1(&current_policy_inputs) {
                    eprintln!("aos-sandbox-policy-authorityd: Stop cleanup disposition: {cause}");
                    if let Some(cause) = flight.failure() {
                        eprintln!("aos-sandbox-policy-authorityd: {cause}");
                    }
                    std::process::exit(1);
                }
                continue;
            }
            if prelude.purpose_v1() == Some(aos_sandbox::policy_compiler::RootPolicyPurposeV1::DeletePlanning) {
                if let Err(cause) = prelude.serve_delete_planning_once_v1() {
                    eprintln!("aos-sandbox-policy-authorityd: Delete planning disposition: {cause}");
                    if let Some(view) = flight.delete_planning_failure_view_v1() {
                        eprintln!("aos-sandbox-policy-authorityd: {view}");
                    } else if let Some(cause) = flight.failure() {
                        eprintln!("aos-sandbox-policy-authorityd: {cause}");
                    }
                    std::process::exit(1);
                }
                continue;
            }
            if prelude.purpose_v1() == Some(aos_sandbox::policy_compiler::RootPolicyPurposeV1::FinalityRecover) {
                let mut attempt = match prelude.into_finality_recover_receiving_v1() {
                    Ok(attempt) => attempt,
                    Err(mut prelude) => {
                        let _owed = prelude.finish_negative_once_v1();
                        std::process::exit(1);
                    }
                };
                if attempt.receive_once_v1().is_err() {
                    let _owed = attempt.finish_negative_once();
                    if let Some(view) = attempt.property_failure_view_v1() {
                        eprintln!("aos-sandbox-policy-authorityd: finality Recover: {view}");
                    } else if let Some(cause) = attempt.failure() {
                        eprintln!("aos-sandbox-policy-authorityd: finality Recover: {cause}");
                    }
                    std::process::exit(1);
                }
                if let Err(cause) = attempt.finish_positive_once() {
                    eprintln!("aos-sandbox-policy-authorityd: finality Recover disposition: {cause}");
                    if let Some(cause) = flight.failure() {
                        eprintln!("aos-sandbox-policy-authorityd: {cause}");
                    }
                    std::process::exit(1);
                }
                continue;
            }
            if prelude.purpose_v1() == Some(aos_sandbox::policy_compiler::RootPolicyPurposeV1::StartAssignmentInputs) {
                let mut attempt = match prelude.into_start_assignment_inputs_receiving_v2() {
                    Ok(attempt) => attempt,
                    Err(mut prelude) => {
                        let _owed = prelude.finish_negative_once_v1();
                        std::process::exit(1);
                    }
                };
                if attempt.receive_once_v2(&current_policy_inputs).is_err() {
                    let _owed = attempt.finish_negative_once();
                    if let Some(cause) = attempt.failure() {
                        eprintln!("aos-sandbox-policy-authorityd: Start policy inputs: {cause}");
                    }
                    std::process::exit(1);
                }
                if let Err(cause) = attempt.finish_positive_once() {
                    eprintln!("aos-sandbox-policy-authorityd: Start policy input disposition: {cause}");
                    if let Some(cause) = flight.failure() {
                        eprintln!("aos-sandbox-policy-authorityd: {cause}");
                    }
                    std::process::exit(1);
                }
                continue;
            }
            if prelude.purpose_v1() == Some(aos_sandbox::policy_compiler::RootPolicyPurposeV1::MaintenanceStorage) {
                let mut attempt = match prelude.into_maintenance_storage_receiving_v3() {
                    Ok(attempt) => attempt,
                    Err(mut original) => { let _owed = original.finish_negative_once_v1(); std::process::exit(1); }
                };
                if attempt.receive_unsigned_once_v3(&current_policy_inputs).is_err()
                    || attempt.receive_final_once_v3(&current_policy_inputs).is_err() {
                    let _owed = attempt.finish_negative_once_v3();
                    if let Some(cause) = attempt.failure() { eprintln!("aos-sandbox-policy-authorityd: Maintenance Storage: {cause}"); }
                    std::process::exit(1);
                }
                if let Err(cause) = attempt.finish_positive_once_v3() {
                    eprintln!("aos-sandbox-policy-authorityd: Maintenance Storage disposition: {cause}");
                    if let Some(cause) = flight.failure() { eprintln!("aos-sandbox-policy-authorityd: {cause}"); }
                    std::process::exit(1);
                }
                continue;
            }
            if prelude.purpose_v1() == Some(aos_sandbox::policy_compiler::RootPolicyPurposeV1::HostLaunch) {
                let mut attempt = match prelude.into_start_resource_receiving_v2() {
                    Ok(attempt) => attempt,
                    Err(mut prelude) => { let _owed = prelude.finish_negative_once_v1(); std::process::exit(1); }
                };
                if attempt.receive_unsigned_once_v2(&current_policy_inputs).is_err()
                    || attempt.receive_final_once_v2(&current_policy_inputs).is_err() {
                    let _owed = attempt.finish_negative_once_v2();
                    if let Some(cause) = attempt.failure() { eprintln!("aos-sandbox-policy-authorityd: Start Network: {cause}"); }
                    std::process::exit(1);
                }
                if let Err(cause) = attempt.finish_positive_once_v2() {
                    eprintln!("aos-sandbox-policy-authorityd: Start Network disposition: {cause}");
                    if let Some(cause) = flight.failure() { eprintln!("aos-sandbox-policy-authorityd: {cause}"); }
                    std::process::exit(1);
                }
                continue;
            }
            if prelude.purpose_v1() == Some(aos_sandbox::policy_compiler::RootPolicyPurposeV1::Apply) {
                let mut attempt = match prelude.into_storage_apply_v1() {
                    Ok(attempt) => attempt,
                    Err(mut prelude) => {
                        let _owed = prelude.finish_negative_once_v1();
                        std::process::exit(1);
                    }
                };
                if attempt.receive_unsigned_once_v1(&current_policy_inputs).is_err()
                    || attempt.receive_final_once_v1(&current_policy_inputs).is_err()
                {
                    let owed = attempt.finish_negative_once();
                    if let Some(cause) = attempt.failure() {
                        eprintln!("aos-sandbox-policy-authorityd: {cause}");
                    }
                    if let Err(cause) = owed {
                        eprintln!("aos-sandbox-policy-authorityd: Apply post: {cause}");
                    }
                    std::process::exit(1);
                }
                // This closes only the verified Root purpose. The Controller
                // still needs its genuine post-ACK native terminal CAS before
                // public Succeeded/STOPPED can become observable.
                if let Err(cause) = attempt.finish_positive_once() {
                    eprintln!("aos-sandbox-policy-authorityd: Apply disposition: {cause}");
                    if let Some(cause) = flight.failure() {
                        eprintln!("aos-sandbox-policy-authorityd: {cause}");
                    }
                    std::process::exit(1);
                }
                continue;
            }
            if prelude.purpose_v1() == Some(aos_sandbox::policy_compiler::RootPolicyPurposeV1::Environment) {
                let mut attempt = match prelude.into_environment_v1() {
                    Ok(attempt) => attempt,
                    Err(mut prelude) => {
                        let _owed = prelude.finish_negative_once_v1();
                        std::process::exit(1);
                    }
                };
                if attempt.serve_once(&current_policy_inputs).is_err() {
                    let owed = attempt.finish_negative_once();
                    if let Some(cause) = attempt.failure() {
                        eprintln!("aos-sandbox-policy-authorityd: {cause}");
                    }
                    if let Err(cause) = owed {
                        eprintln!("aos-sandbox-policy-authorityd: Environment post: {cause}");
                    }
                    std::process::exit(1);
                }
                if let Err(cause) = attempt.finish_positive_once() {
                    eprintln!("aos-sandbox-policy-authorityd: Environment disposition: {cause}");
                    if let Some(cause) = flight.failure() {
                        eprintln!("aos-sandbox-policy-authorityd: {cause}");
                    }
                    std::process::exit(1);
                }
                continue;
            }
            // Closed owning transfers preserve the same socket, native prefix
            // and absolute cutoff. Other purposes stay rejected until their
            // actual terminal producers are installed; a tag grants nothing.
            let mut attempt = match prelude.into_create_v1() {
                Ok(attempt) => attempt,
                Err(mut prelude) => {
                    let _owed = prelude.finish_negative_once_v1();
                    if let Some(cause) = prelude.failure() {
                        eprintln!("aos-sandbox-policy-authorityd: {cause}");
                    }
                    std::process::exit(1);
                }
            };
            let returned = attempt.serve_once(&current_policy_inputs, source_signer_uid, controller_gid, private);
            if returned.is_err() {
                // The full completion remains inside attempt before same-OFD
                // shutdown and independent Root posts. Nothing unwinds it.
                let negative_post = attempt.finish_negative_once();
                if let Some(view) = attempt.failure_view() {
                    if let Some(cause) = view.cause() {
                        eprintln!("aos-sandbox-policy-authorityd: {cause}");
                    }
                }
                if let Err(later) = &negative_post {
                    eprintln!("aos-sandbox-policy-authorityd: receiving post: {later}");
                }
                std::process::exit(1);
            }
            // This consuming path requires actual Root6 native closure and
            // transfers the same writer pair before disposing positive inputs.
            // The listener then closes this socket and its same-R operation.
            if let Err(cause) = attempt.finish_positive_once() {
                eprintln!("aos-sandbox-policy-authorityd: terminal disposition: {cause}");
                if let Some(cause) = flight.serving_handoff_failure_v1().or_else(|| flight.failure()) {
                    eprintln!("aos-sandbox-policy-authorityd: {cause}");
                }
                std::process::exit(1);
            }
        }
    }

    let listener = bind_policy_socket(Path::new(POLICY_AUTHORITY_SOCKET_PATH_V2))?;
    for accepted in listener.incoming() {
        let stream = accepted?;
        if let Some(owner) = &startup {
            owner.recheck()?;
        }
        if let Err(error) = head_service.serve_original(stream) {
            eprintln!("aos-sandbox-policy-authorityd: rejected head query: {error}");
        }
    }
    Err(io::Error::new(io::ErrorKind::BrokenPipe, "authority listener ended").into())
}

fn finish_startup_journal_names(
    journal: &mut Option<RootPolicyStartupJournalV1>,
) -> Result<(), Box<dyn Error>> {
    let Some(journal) = journal else {
        return Ok(());
    };
    if journal.finish_names_once().is_err() {
        let cause = journal
            .failure()
            .map(ToString::to_string)
            .unwrap_or_else(|| "incomplete Root startup writer".to_owned());
        return Err(io::Error::other(cause).into());
    }
    Ok(())
}

fn serve_held_binding_recovery(
    controller_uid: u32,
    controller_gid: u32,
    startup: Option<
        aos_sandbox::normal_root::ProductionNormalRootStartupV1,
    >,
) -> Result<(), Box<dyn Error>> {
    let listener = bind_policy_socket(Path::new(POLICY_AUTHORITY_SOCKET_PATH_V2))?;
    for accepted in listener.incoming() {
        let mut stream = accepted?;
        if let Some(owner) = &startup {
            owner.recheck()?;
        }
        if let Err(error) = serve_held_binding_request(&mut stream, controller_uid, controller_gid)
        {
            eprintln!("aos-sandbox-policy-authorityd: rejected held Q04 recovery: {error}");
        }
    }
    Err(io::Error::new(io::ErrorKind::BrokenPipe, "authority listener ended").into())
}

fn serve_project_admission_recovery_only(
    controller_uid: u32,
    controller_gid: u32,
    source_signer_uid: u32,
    startup: Option<
        &aos_sandbox::normal_root::ProductionNormalRootStartupV1,
    >,
) -> Result<(), Box<dyn Error>> {
    let listener = bind_policy_socket(Path::new(POLICY_AUTHORITY_SOCKET_PATH_V2))?;
    for accepted in listener.incoming() {
        let mut stream = accepted?;
        if let Some(owner) = startup {
            owner.recheck()?;
        }
        if let Err(error) = serve_project_admission_recovery_request(
            &mut stream,
            controller_uid,
            controller_gid,
            source_signer_uid,
            startup,
        ) {
            eprintln!("aos-sandbox-policy-authorityd: rejected project recovery: {error}");
        }
    }
    Err(io::Error::new(io::ErrorKind::BrokenPipe, "project recovery listener ended").into())
}

fn serve_project_admission_recovery_request(
    stream: &mut std::os::unix::net::UnixStream,
    controller_uid: u32,
    controller_gid: u32,
    source_signer_uid: u32,
    startup: Option<
        &aos_sandbox::normal_root::ProductionNormalRootStartupV1,
    >,
) -> Result<(), Box<dyn Error>> {
    require_controller_peer(stream, controller_uid, controller_gid)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let (request, mode) = read_head_request(stream, || Ok(()))?;
    if matches!(mode, HeadRequestMode::SourceFirstSuccessor) {
        let mut attempt = RootFirstSourceSuccessorAttemptV2::new(
            stream, startup, request, RootFirstSourceSuccessorRouteV2::Historical,
            controller_uid, controller_gid, controller_uid, source_signer_uid,
        );
        let returned = attempt.serve_once();
        if returned.is_err() {
            let _first_cause = attempt.first_cause();
            // The original accepted stream, opening/native Results and Root
            // writer remain resident through terminal exit, never local retry.
            std::process::exit(1);
        }
        return Ok(());
    }
    if matches!(mode, HeadRequestMode::SourceResourceGlobalGenesis) {
        let mut attempt = RootGlobalGenesisAttemptV2::new(
            stream, startup, request, RootFirstSourceSuccessorRouteV2::Historical,
            controller_uid, controller_gid, controller_uid, source_signer_uid,
        );
        let returned = attempt.serve_once();
        if returned.is_err() {
            let _first_cause = attempt.first_cause();
            std::process::exit(1);
        }
        return Ok(());
    }
    if matches!(mode, HeadRequestMode::SourceProjectGenesis) {
        let mut attempt = RootProjectGenesisAttemptV3::new(
            stream, startup, request, RootFirstSourceSuccessorRouteV2::Historical,
            controller_uid, controller_gid, controller_uid, source_signer_uid,
        );
        let returned = attempt.serve_once();
        if returned.is_err() { let _first_cause = attempt.first_cause(); std::process::exit(1); }
        return Ok(());
    }
    if matches!(mode, HeadRequestMode::SourceProjectSuccessor) {
        let mut attempt = RootProjectSuccessorAttemptV3::new(
            stream, startup, request, RootFirstSourceSuccessorRouteV2::Historical,
            controller_uid, controller_gid, controller_uid, source_signer_uid,
        );
        let returned = attempt.serve_once();
        if returned.is_err() { let _first_cause = attempt.first_cause(); std::process::exit(1); }
        return Ok(());
    }
    if !project_recovery_mode_allowed(mode) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "recovery-only Root cannot issue fresh policy authority",
        )
        .into());
    }
    require_no_fixed_closed_policy_binding_hold_v1()?;
    match mode {
        HeadRequestMode::SourceGenesis => serve_root_source_genesis_recovery_v1(
            stream,
            startup,
            request[8..24].try_into()?,
            controller_uid,
            controller_gid,
            controller_uid,
            source_signer_uid,
        )
        .map_err(Into::into),
        HeadRequestMode::ProjectNegativeIntent => {
            serve_project_negative_intent(stream, &request[8..24], controller_uid)
        }
        HeadRequestMode::ProjectHistoryFloorReplay => {
            serve_project_history_floor_replay(stream, &request[8..24])
        }
        HeadRequestMode::ProjectHistoryRetirement => serve_project_history_retirement(
            stream,
            &request[8..24],
            controller_uid,
            source_signer_uid,
            controller_gid,
        ),
        HeadRequestMode::ProjectAdmissionOutcomeReplay => {
            serve_project_admission_outcome_replay(stream, &request[8..24])
        }
        HeadRequestMode::ProjectAdmissionCurrentStage => {
            serve_project_admission_current_stage(stream, &request[8..24])
        }
        HeadRequestMode::ProjectReservationCancelReplay => {
            serve_project_reservation_cancel_replay(stream, &request[8..24])
        }
        HeadRequestMode::ProjectAdmissionIntentReplay => {
            serve_project_intent_replay(stream, &request[8..24])
        }
        HeadRequestMode::ProjectReservationCancel => {
            serve_project_reservation_cancel(stream, &request[8..24])
        }
        HeadRequestMode::ProjectAdmissionAbort => {
            let pin = recover_fixed_root_project_source_pin_v1()?.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "historical Source pin absent",
                )
            })?;
            serve_project_admission_abort(
                stream,
                &request[8..24],
                &pin,
                source_signer_uid,
                controller_gid,
            )
        }
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "unknown recovery mode").into()),
    }
}

fn project_recovery_mode_allowed(mode: HeadRequestMode) -> bool {
    matches!(
        mode,
        HeadRequestMode::SourceGenesis
            | HeadRequestMode::SourceResourceGlobalGenesis
            | HeadRequestMode::SourceFirstSuccessor
            | HeadRequestMode::SourceProjectGenesis
            | HeadRequestMode::SourceProjectSuccessor
            | HeadRequestMode::ProjectNegativeIntent
            | HeadRequestMode::ProjectHistoryFloorReplay
            | HeadRequestMode::ProjectHistoryRetirement
            | HeadRequestMode::ProjectAdmissionOutcomeReplay
            | HeadRequestMode::ProjectAdmissionCurrentStage
            | HeadRequestMode::ProjectReservationCancelReplay
            | HeadRequestMode::ProjectAdmissionIntentReplay
            | HeadRequestMode::ProjectReservationCancel
            | HeadRequestMode::ProjectAdmissionAbort
    )
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
            | HeadRequestMode::RootV8EffectAck
            | HeadRequestMode::RootV8EffectAckReplay
            | HeadRequestMode::RootV8Terminal
            | HeadRequestMode::RootV8TerminalReplay
            | HeadRequestMode::RootV8TerminalRelease
            | HeadRequestMode::RootV8TerminalReleaseReplay
            | HeadRequestMode::RootV8SettledGrant
            | HeadRequestMode::ProjectAdmissionOutcomeReplay
            | HeadRequestMode::ClosedBindingSourceCasReplay
    ) {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "replay only").into());
    }
    match mode {
        HeadRequestMode::ClosedBindingReplay => {
            serve_closed_binding_replay(stream, &request[8..24])
        }
        HeadRequestMode::RootV8EffectAck => {
            serve_root_v8_effect_ack(stream, &request[8..24], controller_uid)
        }
        HeadRequestMode::RootV8EffectAckReplay => {
            serve_root_v8_effect_ack_replay(stream, &request[8..24])
        }
        HeadRequestMode::RootV8Terminal => {
            serve_root_v8_terminal(stream, &request[8..24], controller_uid)
        }
        HeadRequestMode::RootV8TerminalReplay => {
            serve_root_v8_terminal_replay(stream, &request[8..24])
        }
        HeadRequestMode::RootV8TerminalRelease => {
            serve_root_v8_terminal_release(stream, &request[8..24], controller_uid)
        }
        HeadRequestMode::RootV8TerminalReleaseReplay => {
            serve_root_v8_terminal_release_replay(stream, &request[8..24])
        }
        HeadRequestMode::RootV8SettledGrant => serve_root_v8_settled_grant(stream, &request[8..24]),
        HeadRequestMode::ProjectAdmissionOutcomeReplay => {
            serve_project_admission_outcome_replay(stream, &request[8..24])
        }
        HeadRequestMode::ProjectAdmissionCurrentStage => {
            serve_project_admission_current_stage(stream, &request[8..24])
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

fn require_absent_git_evidence_credential() -> io::Result<()> {
    let path = Path::new(CREDENTIAL_ROOT).join("git-evidence-provision-v1");
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Git evidence credential is forbidden outside normal current startup",
        )),
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
    if &request[..8] == aos_sandbox::git::GIT_EVIDENCE_VIEW_BOOTSTRAP_MAGIC_V1 {
        // Complete discrimination DATA only. The same accepted stream enters
        // its prearmed capsule before every fallible new-purpose check/gate.
        return Ok((request, HeadRequestMode::GitEvidenceView));
    }
    if &request[..8] == aos_sandbox::policy_compiler::ROOT_CREATE_Q04_QUERY_MAGIC_V1 {
        // Discrimination is not authority. The actual accepted owner must be
        // parked before even missing-startup or malformed-purpose refusal.
        return Ok((request, HeadRequestMode::CreateQ04));
    }
    if &request[..8] == genesis_wire::ROOT_FIRST_SOURCE_SUCCESSOR_QUERY_MAGIC_V2 {
        // Complete inert discrimination only. The same accepted original is
        // parked before nonce, startup, Root hold, or new-purpose validation.
        return Ok((request, HeadRequestMode::SourceFirstSuccessor));
    }
    if &request[..8] == genesis_wire::ROOT_SOURCE_PROJECT_GENESIS_QUERY_MAGIC_V3 {
        // Complete inert recognition only; the same original is parked before
        // new-purpose admission, fixed Root opening or Source signer work.
        return Ok((request, HeadRequestMode::SourceProjectGenesis));
    }
    if &request[..8] == genesis_wire::ROOT_PROJECT_SOURCE_SUCCESSOR_QUERY_MAGIC_V3 {
        // Only complete inert discrimination precedes parking the same accepted
        // stream; this packet selects no detached Root or admission authority.
        return Ok((request, HeadRequestMode::SourceProjectSuccessor));
    }
    if &request[..8] == aos_sandbox::policy_compiler::GIT_COVERAGE_ROOT_BOOTSTRAP_MAGIC_V1 {
        // Inert complete recognition only. The selected owner parks this same
        // startup, stream and packet before new-purpose checks or writer opens.
        return Ok((request, HeadRequestMode::GitCoverageEnrollment));
    }
    if &request[..8]
        == aos_sandbox::policy_compiler::consumer_read_flight::CONSUMER_READ_BOOTSTRAP_MAGIC_V1
    {
        if request[8..24] == [0; 16] || request[24..32] == [0; 8] {
            return Err(
                io::Error::new(io::ErrorKind::InvalidData, "invalid PRE-ROOT bootstrap").into(),
            );
        }
        // Inert discrimination only. The mandatory normal startup check is
        // separate, in the owned dispatcher; only this per-flight Root gate
        // is deferred. Recovery permission sets are intentionally unchanged.
        return Ok((request, HeadRequestMode::ConsumerReadPreRoot));
    }
    let mode = match request.get(..8) {
        Some(magic) if magic == genesis_wire::ROOT_SOURCE_RESOURCE_GENESIS_QUERY_MAGIC_V2 => {
            if request[8..24] == [0; 16] || request[24..] != [0; 8] {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid resource Global query").into());
            }
            HeadRequestMode::SourceResourceGlobalGenesis
        }
        Some(magic) if magic == ROOT_SOURCE_GENESIS_QUERY_MAGIC_V1 => {
            HeadRequestMode::SourceGenesis
        }
        Some(magic) if magic == POLICY_BINDING_QUERY_MAGIC_V4 => HeadRequestMode::ClosedBinding,
        Some(magic) if magic == POLICY_BINDING_REPLAY_QUERY_MAGIC_V5 => {
            HeadRequestMode::ClosedBindingReplay
        }
        Some(magic) if magic == ROOT_V8_ACK_QUERY_MAGIC => HeadRequestMode::RootV8EffectAck,
        Some(magic) if magic == ROOT_V8_ACK_REPLAY_QUERY_MAGIC => {
            HeadRequestMode::RootV8EffectAckReplay
        }
        Some(magic) if magic == ROOT_V8_TERMINAL_QUERY_MAGIC => HeadRequestMode::RootV8Terminal,
        Some(magic) if magic == ROOT_V8_TERMINAL_REPLAY_QUERY_MAGIC => {
            HeadRequestMode::RootV8TerminalReplay
        }
        Some(magic) if magic == ROOT_V8_RELEASE_QUERY_MAGIC => {
            HeadRequestMode::RootV8TerminalRelease
        }
        Some(magic) if magic == ROOT_V8_RELEASE_REPLAY_QUERY_MAGIC => {
            HeadRequestMode::RootV8TerminalReleaseReplay
        }
        Some(magic) if magic == ROOT_V8_SETTLED_QUERY_MAGIC => HeadRequestMode::RootV8SettledGrant,
        Some(magic) if magic == ROOT_PROJECT_ADMISSION_OUTCOME_QUERY_MAGIC => {
            HeadRequestMode::ProjectAdmissionOutcomeReplay
        }
        Some(magic) if magic == ROOT_PROJECT_ADMISSION_INTENT_QUERY_MAGIC => {
            HeadRequestMode::ProjectAdmissionIntent
        }
        Some(magic) if magic == ROOT_PROJECT_NEGATIVE_INTENT_QUERY_MAGIC => {
            HeadRequestMode::ProjectNegativeIntent
        }
        Some(magic) if magic == ROOT_PROJECT_ADMISSION_INTENT_REPLAY_MAGIC => {
            HeadRequestMode::ProjectAdmissionIntentReplay
        }
        Some(magic) if magic == ROOT_PROJECT_ADMISSION_STAGE_QUERY_MAGIC => {
            HeadRequestMode::ProjectAdmissionStage
        }
        Some(magic) if magic == ROOT_PROJECT_ADMISSION_COMMIT_QUERY_MAGIC => {
            HeadRequestMode::ProjectAdmissionCommit
        }
        Some(magic) if magic == ROOT_PROJECT_ADMISSION_ABORT_QUERY_MAGIC => {
            HeadRequestMode::ProjectAdmissionAbort
        }
        Some(magic) if magic == ROOT_PROJECT_ADMISSION_CURRENT_QUERY_MAGIC => {
            HeadRequestMode::ProjectAdmissionCurrentStage
        }
        Some(magic) if magic == ROOT_PROJECT_RESERVATION_CANCEL_MAGIC => {
            HeadRequestMode::ProjectReservationCancel
        }
        Some(magic) if magic == ROOT_PROJECT_RESERVATION_CANCEL_QUERY_MAGIC => {
            HeadRequestMode::ProjectReservationCancelReplay
        }
        Some(magic) if magic == ROOT_PROJECT_HISTORY_FLOOR_QUERY_MAGIC => {
            HeadRequestMode::ProjectHistoryFloorReplay
        }
        Some(magic) if magic == ROOT_PROJECT_HISTORY_RETIRE_MAGIC => {
            HeadRequestMode::ProjectHistoryRetirement
        }
        Some(magic) if magic == POLICY_BINDING_STAGE_QUERY_MAGIC_V4 => {
            HeadRequestMode::ClosedBindingStage
        }
        Some(magic) if magic == POLICY_BINDING_PREVIEW_QUERY_MAGIC_V4 => {
            HeadRequestMode::ClosedBindingPreview
        }
        Some(magic) if magic == POLICY_BINDING_SOURCE_FLIGHT_REPLAY_QUERY_MAGIC_V7 => {
            HeadRequestMode::ClosedBindingSourceTerminalReplay
        }
        Some(magic) if magic == POLICY_BINDING_SOURCE_FLIGHT_REPLAY_QUERY_MAGIC_V8 => {
            HeadRequestMode::ClosedBindingSourceCasReplay
        }
        Some(magic) if magic == POLICY_CACHE_SIGNER_QUERY_MAGIC_V6 => {
            HeadRequestMode::StagedCacheSigner
        }
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid head query").into()),
    };
    if request[24..] != [0; 8] {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid head query").into());
    }
    // Legacy Q04 never selects the current original-Q04 owner. Refuse it
    // before sending a receipt or opening Root custody.
    if matches!(mode, HeadRequestMode::ClosedBinding) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "closed policy binding admission is unavailable",
        )
        .into());
    }
    if matches!(
        mode,
        HeadRequestMode::SourceGenesis
            | HeadRequestMode::SourceResourceGlobalGenesis
            | HeadRequestMode::ClosedBindingReplay
            | HeadRequestMode::ClosedBindingStage
            | HeadRequestMode::ClosedBindingPreview
            | HeadRequestMode::ClosedBindingSourceTerminalReplay
            | HeadRequestMode::ClosedBindingSourceCasReplay
            | HeadRequestMode::RootV8EffectAck
            | HeadRequestMode::RootV8EffectAckReplay
            | HeadRequestMode::RootV8Terminal
            | HeadRequestMode::RootV8TerminalReplay
            | HeadRequestMode::RootV8TerminalRelease
            | HeadRequestMode::RootV8TerminalReleaseReplay
            | HeadRequestMode::RootV8SettledGrant
            | HeadRequestMode::ProjectAdmissionOutcomeReplay
            | HeadRequestMode::ProjectAdmissionIntent
            | HeadRequestMode::ProjectNegativeIntent
            | HeadRequestMode::ProjectAdmissionIntentReplay
            | HeadRequestMode::ProjectAdmissionStage
            | HeadRequestMode::ProjectAdmissionCommit
            | HeadRequestMode::ProjectAdmissionAbort
            | HeadRequestMode::ProjectAdmissionCurrentStage
            | HeadRequestMode::ProjectReservationCancel
            | HeadRequestMode::ProjectReservationCancelReplay
            | HeadRequestMode::ProjectHistoryFloorReplay
            | HeadRequestMode::ProjectHistoryRetirement
    ) {
        if request[8..24] == [0; 16] {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "zero Q04 query nonce").into());
        }
    }
    if !matches!(
        mode,
        HeadRequestMode::ClosedBindingReplay
            | HeadRequestMode::RootV8EffectAck
            | HeadRequestMode::RootV8EffectAckReplay
            | HeadRequestMode::RootV8Terminal
            | HeadRequestMode::RootV8TerminalReplay
            | HeadRequestMode::RootV8TerminalRelease
            | HeadRequestMode::RootV8TerminalReleaseReplay
            | HeadRequestMode::RootV8SettledGrant
            | HeadRequestMode::ProjectAdmissionOutcomeReplay
            | HeadRequestMode::ProjectAdmissionCurrentStage
            | HeadRequestMode::ProjectReservationCancelReplay
            | HeadRequestMode::ProjectHistoryFloorReplay
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

fn require_pre_root_startup(
    startup: Option<&aos_sandbox::normal_root::ProductionNormalRootStartupV1>,
) -> io::Result<&aos_sandbox::normal_root::ProductionNormalRootStartupV1> {
    startup.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "PRE-ROOT requires actual normal startup",
        )
    })
}

#[allow(clippy::too_many_arguments)]
fn serve_original_create_q04(
    attempt: &mut aos_sandbox::policy_compiler::OriginalRootCreateQ04AttemptV1<'_>,
    source_signer_uid: u32,
    controller_gid: u32,
    packet: &[u8],
    inputs: &PolicyDeploymentInputsV1<'_>,
    deployment_key: &VerifyingKey,
    deployment_generation: u64,
    explicit_project: Option<(&[u8], &[u8])>,
    project_key: &VerifyingKey,
    project_generation: u64,
) -> Result<(), ()> {
    use aos_sandbox_services::source_genesis_flight::{
        prepare_root_create_q04_existing_gen1_v1,
        refresh_root_create_q04_gen1_v1,
    };

    prepare_root_create_q04_existing_gen1_v1(attempt, source_signer_uid, controller_gid)?;
    attempt.send_nonissuing_preview(
        packet, deployment_generation, deployment_key, explicit_project,
        project_generation, project_key, inputs,
    )?;
    attempt.prepare_publication_data()?;

    // C1 and Source acquisition each change a real signed gen1 observation.
    // Cache acquisition does not change either of those original writers.
    for _ in 0..2 {
        refresh_root_create_q04_gen1_v1(attempt, source_signer_uid, controller_gid)?;
    }
    attempt.receive_held_claim()?;
    attempt.commit_held_root_binding()?;
    attempt.publish_held_policy()?;
    attempt.publish_decision()?;

    refresh_root_create_q04_gen1_v1(attempt, source_signer_uid, controller_gid)?; // C2
    attempt.consume_policy_acknowledgement()?;
    for _ in 0..2 { // C3, C4
        refresh_root_create_q04_gen1_v1(attempt, source_signer_uid, controller_gid)?;
    }
    attempt.authorize_lower_release()?;

    for _ in 0..2 { // Source release, C5 atomic released settlement
        refresh_root_create_q04_gen1_v1(attempt, source_signer_uid, controller_gid)?;
    }
    attempt.settle_lower_release()?;
    for _ in 0..3 { // C6, Source clear after Cache clear, C7
        refresh_root_create_q04_gen1_v1(attempt, source_signer_uid, controller_gid)?;
    }
    attempt.acknowledge_lower_clearance()?;

    // Root7 does not release this owner. The fresh C8 Complete/Source packet
    // is the final same-flight observation before actual bounded shutdown.
    refresh_root_create_q04_gen1_v1(attempt, source_signer_uid, controller_gid)?;
    attempt.finish_original_clearance()
}

// This private driver borrows the exact already-verified startup inputs.
// Both listener paths invoke this same existing handler with the same mapping.
struct CurrentRootHeadServiceV1<'input, 'startup> {
    startup: Option<&'startup aos_sandbox::normal_root::ProductionNormalRootStartupV1>,
    controller_uid: u32,
    controller_gid: u32,
    cache_signer_uid: u32,
    source_signer_uid: u32,
    packet: &'input [u8],
    inputs: &'input PolicyDeploymentInputsV1<'input>,
    verifying_key: &'input VerifyingKey,
    deployment_signer_generation: u64,
    explicit_project: Option<(&'input [u8], &'input [u8])>,
    project_key: &'input VerifyingKey,
    project_signer_generation: u64,
    cache_pin: Option<&'input [u8]>,
    source_pin: Option<&'input [u8]>,
    controller_hold_pin: Option<&'input [u8]>,
}

impl CurrentRootHeadServiceV1<'_, '_> {
    fn serve_original(&self, stream: std::os::unix::net::UnixStream) -> Result<(), Box<dyn Error>> {
        serve_current_head(
            stream, self.startup, self.controller_uid, self.controller_gid,
            self.cache_signer_uid, self.source_signer_uid, self.packet, self.inputs,
            self.verifying_key, self.deployment_signer_generation, self.explicit_project,
            self.project_key, self.project_signer_generation, self.cache_pin,
            self.source_pin, self.controller_hold_pin,
        )
    }
}

fn serve_current_head(
    mut original: std::os::unix::net::UnixStream,
    startup: Option<
        &aos_sandbox::normal_root::ProductionNormalRootStartupV1,
    >,
    controller_uid: u32,
    controller_gid: u32,
    cache_signer_uid: u32,
    source_signer_uid: u32,
    packet: &[u8],
    inputs: &PolicyDeploymentInputsV1<'_>,
    verifying_key: &VerifyingKey,
    deployment_signer_generation: u64,
    explicit_project: Option<(&[u8], &[u8])>,
    project_key: &VerifyingKey,
    project_signer_generation: u64,
    cache_pin: Option<&[u8]>,
    source_pin: Option<&[u8]>,
    controller_hold_pin: Option<&[u8]>,
) -> Result<(), Box<dyn Error>> {
    let stream = &mut original;
    require_controller_peer(stream, controller_uid, controller_gid)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    let (request, mode) = read_head_request(stream, || {
        if let Some(owner) = startup {
            owner.recheck()?;
        }
        require_no_fixed_closed_policy_binding_hold_v1()?;
        Ok(())
    })?;
    if matches!(mode, HeadRequestMode::SourceFirstSuccessor) {
        let mut attempt = RootFirstSourceSuccessorAttemptV2::new(
            stream, startup, request, RootFirstSourceSuccessorRouteV2::Current,
            controller_uid, controller_gid, controller_uid, source_signer_uid,
        );
        let returned = attempt.serve_once();
        if returned.is_err() {
            let _first_cause = attempt.first_cause();
            std::process::exit(1);
        }
        return Ok(());
    }
    if matches!(mode, HeadRequestMode::SourceResourceGlobalGenesis) {
        let mut attempt = RootGlobalGenesisAttemptV2::new(
            stream, startup, request, RootFirstSourceSuccessorRouteV2::Current,
            controller_uid, controller_gid, controller_uid, source_signer_uid,
        );
        let returned = attempt.serve_once();
        if returned.is_err() {
            let _first_cause = attempt.first_cause();
            std::process::exit(1);
        }
        return Ok(());
    }
    if matches!(mode, HeadRequestMode::SourceProjectGenesis) {
        let mut attempt = RootProjectGenesisAttemptV3::new(
            stream, startup, request, RootFirstSourceSuccessorRouteV2::Current,
            controller_uid, controller_gid, controller_uid, source_signer_uid,
        );
        let returned = attempt.serve_once();
        if returned.is_err() { let _first_cause = attempt.first_cause(); std::process::exit(1); }
        return Ok(());
    }
    if matches!(mode, HeadRequestMode::SourceProjectSuccessor) {
        let mut attempt = RootProjectSuccessorAttemptV3::new(
            stream, startup, request, RootFirstSourceSuccessorRouteV2::Current,
            controller_uid, controller_gid, controller_uid, source_signer_uid,
        );
        let returned = attempt.serve_once();
        if returned.is_err() { let _first_cause = attempt.first_cause(); std::process::exit(1); }
        return Ok(());
    }
    if matches!(mode, HeadRequestMode::GitEvidenceView) {
        let mut attempt = aos_sandbox::git::RootGitEvidenceViewAttemptV1::new(
            startup, original, request,
        );
        if let Err(error) = attempt.serve_once() {
            // Neither fallible diagnostics nor an ordinary return may drop
            // the original failed flight/writer before terminal process exit.
            let _ = writeln!(std::io::stderr().lock(), "aos-sandbox-policy-authorityd: {error}");
            std::process::exit(1);
        }
        return Ok(());
    }
    if matches!(mode, HeadRequestMode::CreateQ04) {
        let mut attempt = aos_sandbox::policy_compiler::OriginalRootCreateQ04AttemptV1::new(
            original, startup, request, controller_uid, controller_gid,
            controller_uid, cache_signer_uid,
        );
        let returned = serve_original_create_q04(
            &mut attempt, source_signer_uid, controller_gid,
            packet, inputs, verifying_key, deployment_signer_generation,
            explicit_project, project_key, project_signer_generation,
        );
        if returned.is_err() {
            // The first cause, original partials, both actual Root writers and
            // shutdown result are resident before diagnostics or process exit.
            let _ = writeln!(std::io::stderr().lock(), "aos-sandbox-policy-authorityd: original Q04 cut refused");
            std::process::exit(1);
        }
        return Ok(());
    }
    if matches!(mode, HeadRequestMode::GitCoverageEnrollment) {
        let mut attempt = aos_sandbox::policy_compiler::RootGitCoverageEnrollmentOwnerV1::new(
            startup, original, request,
        );
        if let Err(error) = attempt.serve_once(
            packet, inputs, deployment_signer_generation, verifying_key,
            project_signer_generation, project_key,
        ) {
            // Failed original writers, IO and typed causes stay resident until
            // terminal exit; fallible diagnostics cannot select local disposal.
            let _ = writeln!(std::io::stderr().lock(), "aos-sandbox-policy-authorityd: {error}");
            std::process::exit(1);
        }
        return Ok(());
    }
    if matches!(mode, HeadRequestMode::ConsumerReadPreRoot) {
        let owner = require_pre_root_startup(startup)?;
        // The accepted descriptor is moved exactly once. All old modes keep
        // borrowing this same stream; no clone or competing reader is made.
        return aos_sandbox::policy_compiler::consumer_read_flight::serve_consumer_read_policy_state_v1(
            original.into(), owner, request).map_err(Into::into);
    }
    if matches!(mode, HeadRequestMode::SourceGenesis) {
        // The Source signer process UID is separate from the physical Source
        // journal owner. The latter is explicitly configured as Controller's
        // existing UID by the installed Source owner and read-only view.
        return serve_root_source_genesis_flight_v1(
            stream,
            startup,
            request[8..24].try_into()?,
            controller_uid,
            controller_gid,
            controller_uid,
            source_signer_uid,
        )
        .map_err(Into::into);
    }
    if matches!(mode, HeadRequestMode::ClosedBindingReplay) {
        serve_closed_binding_replay(stream, &request[8..24])?;
        return Ok(());
    }
    if matches!(mode, HeadRequestMode::RootV8EffectAck) {
        serve_root_v8_effect_ack(stream, &request[8..24], controller_uid)?;
        return Ok(());
    }
    if matches!(mode, HeadRequestMode::RootV8EffectAckReplay) {
        serve_root_v8_effect_ack_replay(stream, &request[8..24])?;
        return Ok(());
    }
    if matches!(mode, HeadRequestMode::RootV8Terminal) {
        serve_root_v8_terminal(stream, &request[8..24], controller_uid)?;
        return Ok(());
    }
    if matches!(mode, HeadRequestMode::RootV8TerminalReplay) {
        serve_root_v8_terminal_replay(stream, &request[8..24])?;
        return Ok(());
    }
    if matches!(mode, HeadRequestMode::RootV8TerminalRelease) {
        serve_root_v8_terminal_release(stream, &request[8..24], controller_uid)?;
        return Ok(());
    }
    if matches!(mode, HeadRequestMode::RootV8TerminalReleaseReplay) {
        serve_root_v8_terminal_release_replay(stream, &request[8..24])?;
        return Ok(());
    }
    if matches!(mode, HeadRequestMode::RootV8SettledGrant) {
        serve_root_v8_settled_grant(stream, &request[8..24])?;
        return Ok(());
    }
    if matches!(mode, HeadRequestMode::ProjectAdmissionOutcomeReplay) {
        serve_project_admission_outcome_replay(stream, &request[8..24])?;
        return Ok(());
    }
    if matches!(mode, HeadRequestMode::ProjectAdmissionCurrentStage) {
        serve_project_admission_current_stage(stream, &request[8..24])?;
        return Ok(());
    }
    if matches!(mode, HeadRequestMode::ProjectReservationCancelReplay) {
        serve_project_reservation_cancel_replay(stream, &request[8..24])?;
        return Ok(());
    }
    if matches!(mode, HeadRequestMode::ProjectAdmissionIntentReplay) {
        serve_project_intent_replay(stream, &request[8..24])?;
        return Ok(());
    }
    if matches!(mode, HeadRequestMode::ProjectNegativeIntent) {
        return serve_project_negative_intent(stream, &request[8..24], controller_uid);
    }
    if matches!(mode, HeadRequestMode::ProjectHistoryFloorReplay) {
        return serve_project_history_floor_replay(stream, &request[8..24]);
    }
    if matches!(mode, HeadRequestMode::ProjectHistoryRetirement) {
        return serve_project_history_retirement(
            stream,
            &request[8..24],
            controller_uid,
            source_signer_uid,
            controller_gid,
        );
    }
    if matches!(mode, HeadRequestMode::ProjectAdmissionIntent) {
        let mut reservation_bytes = [0; SOURCE_PROJECT_ADMISSION_RESERVATION_BYTES_V1];
        stream.read_exact(&mut reservation_bytes)?;
        require_stream_eof(stream)?;
        let reservation =
            SourceProjectAdmissionReservationV1::from_record_bytes(&reservation_bytes)
                .map_err(aos_sandbox::journal::JournalError::from)?;
        let nonce: [u8; 16] = request[8..24].try_into()?;
        if reservation.client_nonce() != nonce {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "changed intent nonce").into());
        }
        let (project_packet, project_input) = explicit_project.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "explicit project source unavailable",
            )
        })?;
        let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
        let intent = prepare_fixed_root_project_admission_intent_v1(
            reservation,
            project_packet,
            project_input,
            project_key,
            project_signer_generation,
            packet,
            inputs,
            verifying_key,
            deployment_signer_generation,
            now,
        )?;
        stream.write_all(&encode_root_project_intent_reply_v1(nonce, intent)?)?;
        return Ok(());
    }
    if matches!(mode, HeadRequestMode::ProjectReservationCancel) {
        serve_project_reservation_cancel(stream, &request[8..24])?;
        return Ok(());
    }
    if matches!(mode, HeadRequestMode::ProjectAdmissionStage) {
        let mut reservation_bytes = [0; SOURCE_PROJECT_ADMISSION_RESERVATION_BYTES_V1];
        stream.read_exact(&mut reservation_bytes)?;
        require_stream_eof(stream)?;
        let reservation =
            SourceProjectAdmissionReservationV1::from_record_bytes(&reservation_bytes)
                .map_err(aos_sandbox::journal::JournalError::from)?;
        let (project_packet, project_input) = explicit_project.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "explicit project source unavailable",
            )
        })?;
        let controller_pin = controller_hold_pin.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Controller signer pin absent",
            )
        })?;
        let source_pin = source_pin.ok_or_else(|| {
            io::Error::new(io::ErrorKind::PermissionDenied, "Source signer pin absent")
        })?;
        let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
        let nonce: [u8; 16] = request[8..24].try_into()?;
        if reservation.client_nonce() != nonce {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "changed Source reservation nonce",
            )
            .into());
        }
        let signer = PinnedSourceHoldReadbackSignerV1::decode(source_pin)?;
        let reservation_packet = request_root_source_project_reservation_readback_v1(
            reservation,
            &signer,
            source_signer_uid,
            controller_gid,
        )?;
        let stage = stage_fixed_root_project_admission_v1(
            nonce,
            project_packet,
            project_input,
            project_key,
            project_signer_generation,
            packet,
            inputs,
            verifying_key,
            deployment_signer_generation,
            controller_pin,
            source_pin,
            reservation,
            &reservation_packet,
            now,
        )?;
        stream.write_all(&encode_root_project_admission_stage_reply_v1(nonce, stage)?)?;
        return Ok(());
    }
    if matches!(mode, HeadRequestMode::ProjectAdmissionAbort) {
        let source_pin = source_pin.ok_or_else(|| {
            io::Error::new(io::ErrorKind::PermissionDenied, "Source signer pin absent")
        })?;
        serve_project_admission_abort(
            stream,
            &request[8..24],
            source_pin,
            source_signer_uid,
            controller_gid,
        )?;
        return Ok(());
    }
    if matches!(mode, HeadRequestMode::ProjectAdmissionCommit) {
        let (project_packet, project_input) = explicit_project.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "explicit project source unavailable",
            )
        })?;
        let controller_pin = controller_hold_pin.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Controller signer pin absent",
            )
        })?;
        let source_pin = source_pin.ok_or_else(|| {
            io::Error::new(io::ErrorKind::PermissionDenied, "Source signer pin absent")
        })?;
        let mut stage_bytes = [0; 32];
        stream.read_exact(&mut stage_bytes)?;
        let stage_digest = ObjectDigest::from_bytes(stage_bytes);
        let mut controller_packet = [0; CONTROLLER_PROJECT_ADMISSION_READBACK_BYTES_V1];
        stream.read_exact(&mut controller_packet)?;
        let mut source_bytes = [0; SOURCE_PROJECT_ADMISSION_CHALLENGE_BYTES_V1];
        stream.read_exact(&mut source_bytes)?;
        require_stream_eof(stream)?;
        let source_row = SourceProjectAdmissionChallengeV1::from_record_bytes(&source_bytes)
            .map_err(aos_sandbox::journal::JournalError::from)?;
        let stage = recover_fixed_root_project_admission_stage_v1(stage_digest)?;
        if source_row.project() != stage.project()
            || source_row.nonce() != stage.root_nonce()
            || source_row.cut() != stage.cut()
            || source_row.stage() != stage_digest
        {
            return Err(
                io::Error::new(io::ErrorKind::InvalidData, "changed Source challenge").into(),
            );
        }
        let outcome = {
            let signer = PinnedSourceHoldReadbackSignerV1::decode(source_pin)?;
            let challenge = SourceHoldReadbackChallengeV1::new(stage.root_nonce(), stage.cut())?;
            let source_packet = request_root_source_project_admission_readback_v1(
                challenge,
                source_row,
                stage.source_reservation_digest(),
                &signer,
                source_signer_uid,
                controller_gid,
            )?;
            let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
            admit_fixed_root_project_source_from_owner_proofs_v1(
                stage_digest,
                &controller_packet,
                &source_bytes,
                &source_packet,
                controller_pin,
                source_pin,
                controller_uid,
                project_packet,
                project_input,
                project_key,
                project_signer_generation,
                packet,
                inputs,
                verifying_key,
                deployment_signer_generation,
                now,
            )?
        };
        let nonce: [u8; 16] = request[8..24].try_into()?;
        stream.write_all(&encode_root_project_admission_terminal_reply_v1(
            nonce, outcome,
        )?)?;
        return Ok(());
    }
    if matches!(mode, HeadRequestMode::ClosedBindingSourceCasReplay) {
        serve_closed_source_cas_replay_v8(stream, &request[8..24], controller_uid, controller_gid)?;
        return Ok(());
    }
    if matches!(mode, HeadRequestMode::StagedCacheSigner) && request[8..24] == [0; 16]
    {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "zero Cache client nonce").into());
    }
    // Require the selected mode's explicit source before touching the protected root head.
    let (project_packet, project_input) = select_project_source(mode, explicit_project)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
    let now_unix_seconds = i64::try_from(now.as_secs())?;
    let deployment =
        admit_fixed_policy_deployment_head_v1(packet, inputs, verifying_key, now_unix_seconds)?;
    let (selected_project_packet, selected_project_input, receipt_magic, project_expires_at) = {
        let verified = verify_signed_project_policy_source_v2(
            project_packet,
            project_input,
            project_key,
            now_unix_seconds,
        )
        .map_err(aos_sandbox::policy_compiler::PolicyDeploymentHeadErrorV1::from)?;
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
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "closed policy binding admission is unavailable",
        )
        .into());
    }
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

fn require_explicit_project_source(explicit_present: bool) -> io::Result<()> {
    if !explicit_present {
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

fn read_held_root_ack_claim(
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

fn serve_root_v8_effect_ack_replay(
    stream: &mut std::os::unix::net::UnixStream,
    client_nonce: &[u8],
) -> Result<(), Box<dyn Error>> {
    let (binding, epoch) = read_held_root_ack_claim(stream, true)?;
    let ack = recover_fixed_closed_root_v8_effect_ack_v1(binding, epoch)?;
    let nonce: [u8; 16] = client_nonce.try_into()?;
    stream.write_all(&encode_root_v8_ack_reply(nonce, binding, epoch, ack)?)?;
    Ok(())
}

fn serve_root_v8_effect_ack(
    stream: &mut std::os::unix::net::UnixStream,
    client_nonce: &[u8],
    controller_uid: u32,
) -> Result<(), Box<dyn Error>> {
    let (binding, epoch) = read_held_root_ack_claim(stream, false)?;
    let nonce: [u8; 16] = client_nonce.try_into()?;
    let credential = read_optional_pin(Path::new(CREDENTIAL_ROOT), "controller-hold-public-key")?
        .ok_or_else(|| {
        io::Error::new(io::ErrorKind::PermissionDenied, "Controller pin absent")
    })?;
    stream.set_read_timeout(Some(Duration::from_secs(35)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let ack = acknowledge_fixed_closed_root_v8_effect_v1(
        binding,
        epoch,
        controller_uid,
        &credential,
        |challenge| {
            let mut frame = [0; ROOT_V8_ACK_CHALLENGE_FRAME_BYTES];
            frame[..8].copy_from_slice(ROOT_V8_ACK_CHALLENGE_MAGIC);
            frame[8..24].copy_from_slice(&nonce);
            frame[24..40].copy_from_slice(&challenge.nonce());
            frame[40..72].copy_from_slice(challenge.cut().as_bytes());
            stream.write_all(&frame)?;
            read_root_v8_effect_ack_submission(stream, nonce)
        },
    )?;
    stream.write_all(&encode_root_v8_ack_reply(nonce, binding, epoch, Some(ack))?)?;
    Ok(())
}

fn read_root_v8_effect_ack_submission(
    stream: &mut std::os::unix::net::UnixStream,
    nonce: [u8; 16],
) -> io::Result<Vec<u8>> {
    read_root_ack_submission::<ROOT_V8_ACK_SUBMIT_FRAME_BYTES>(
        stream,
        nonce,
        ROOT_V8_ACK_SUBMIT_MAGIC,
    )
}

fn serve_root_v8_terminal_replay(
    stream: &mut std::os::unix::net::UnixStream,
    client_nonce: &[u8],
) -> Result<(), Box<dyn Error>> {
    let (binding, epoch) = read_held_root_ack_claim(stream, true)?;
    let terminal = recover_fixed_closed_root_v8_verified_terminal_v1(binding, epoch)?;
    let nonce: [u8; 16] = client_nonce.try_into()?;
    stream.write_all(&encode_root_v8_terminal_reply(
        nonce,
        binding,
        epoch,
        terminal.map(|record| record.ack()),
    )?)?;
    Ok(())
}

fn serve_root_v8_terminal_release_replay(
    stream: &mut std::os::unix::net::UnixStream,
    client_nonce: &[u8],
) -> Result<(), Box<dyn Error>> {
    let (binding, epoch) = read_held_root_ack_claim(stream, true)?;
    let custody = recover_fixed_closed_root_v8_terminal_custody_v1(binding, epoch)?;
    let nonce: [u8; 16] = client_nonce.try_into()?;
    stream.write_all(&encode_root_v8_release_reply(
        nonce, binding, epoch, custody,
    )?)?;
    Ok(())
}

fn serve_root_v8_settled_grant(
    stream: &mut std::os::unix::net::UnixStream,
    client_nonce: &[u8],
) -> Result<(), Box<dyn Error>> {
    let (binding, epoch) = read_held_root_ack_claim(stream, true)?;
    let marker = recover_fixed_closed_root_v8_predecessor_settlement_v1(binding, epoch)?;
    let nonce: [u8; 16] = client_nonce.try_into()?;
    stream.write_all(&encode_root_v8_settled_reply_v1(
        nonce, binding, epoch, marker,
    )?)?;
    Ok(())
}

fn serve_project_admission_outcome_replay(
    stream: &mut std::os::unix::net::UnixStream,
    client_nonce: &[u8],
) -> Result<(), Box<dyn Error>> {
    let mut stage_bytes = [0; 32];
    stream.read_exact(&mut stage_bytes)?;
    require_stream_eof(stream)?;
    let stage = ObjectDigest::from_bytes(stage_bytes);
    let outcome = recover_fixed_root_project_admission_outcome_v1(stage)?;
    let nonce: [u8; 16] = client_nonce.try_into()?;
    stream.write_all(&encode_root_project_admission_outcome_reply_v1(
        nonce, stage, outcome,
    )?)?;
    Ok(())
}

fn serve_project_reservation_cancel_replay(
    stream: &mut std::os::unix::net::UnixStream,
    client_nonce: &[u8],
) -> Result<(), Box<dyn Error>> {
    let mut reservation_bytes = [0; 32];
    stream.read_exact(&mut reservation_bytes)?;
    require_stream_eof(stream)?;
    let reservation = ObjectDigest::from_bytes(reservation_bytes);
    let marker = recover_fixed_root_project_reservation_cancellation_v1(reservation)?;
    let nonce: [u8; 16] = client_nonce.try_into()?;
    if marker.is_some_and(|marker| marker.client_nonce() != nonce) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "changed Root cancellation nonce",
        )
        .into());
    }
    stream.write_all(&encode_root_project_reservation_cancel_reply_v1(
        nonce,
        reservation,
        marker,
    )?)?;
    Ok(())
}

fn serve_project_history_floor_replay(
    stream: &mut std::os::unix::net::UnixStream,
    client_nonce: &[u8],
) -> Result<(), Box<dyn Error>> {
    let reservation = read_project_reservation_request(stream, client_nonce)?;
    let floor = recover_fixed_root_project_history_floor_v1(reservation)?;
    stream.write_all(&encode_root_project_history_floor_reply_v1(
        reservation,
        floor,
    )?)?;
    Ok(())
}

fn serve_project_history_retirement(
    stream: &mut std::os::unix::net::UnixStream,
    client_nonce: &[u8],
    controller_uid: u32,
    source_signer_uid: u32,
    controller_gid: u32,
) -> Result<(), Box<dyn Error>> {
    let mut bytes = [0; SOURCE_PROJECT_ADMISSION_RESERVATION_BYTES_V1];
    stream.read_exact(&mut bytes)?;
    let reservation = SourceProjectAdmissionReservationV1::from_record_bytes(&bytes)
        .map_err(aos_sandbox::journal::JournalError::from)?;
    if reservation.client_nonce().as_slice() != client_nonce {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "changed history nonce").into());
    }
    let mut controller_packet = [0; CONTROLLER_PROJECT_TERMINAL_READBACK_BYTES_V1];
    stream.read_exact(&mut controller_packet)?;
    require_stream_eof(stream)?;
    // This untrusted scalar selects only a read-only Source request. Root's
    // held retirement consumer independently verifies the complete Controller
    // packet, both pinned keys, and its own exact terminal before any append.
    let root_terminal = ObjectDigest::from_bytes(controller_packet[228..260].try_into()?);
    let source_pin = recover_fixed_root_project_source_pin_v1()?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "historical Source pin absent",
        )
    })?;
    let signer = PinnedSourceHoldReadbackSignerV1::decode(&source_pin)?;
    let source_packet = aos_sandbox_services::source_signer_exchange::request_root_source_project_completed_terminal_readback_v1(
        reservation, root_terminal, &signer, source_signer_uid, controller_gid)?;
    let floor =
        retire_fixed_root_project_history_v1(&controller_packet, &source_packet, controller_uid)?;
    stream.write_all(&encode_root_project_history_floor_reply_v1(
        reservation,
        Some(floor),
    )?)?;
    Ok(())
}

fn serve_project_admission_current_stage(
    stream: &mut std::os::unix::net::UnixStream,
    client_nonce: &[u8],
) -> Result<(), Box<dyn Error>> {
    require_stream_eof(stream)?;
    let stage = recover_fixed_root_current_project_admission_stage_v1()?;
    let nonce: [u8; 16] = client_nonce.try_into()?;
    stream.write_all(&encode_root_current_project_admission_stage_reply_v1(
        nonce, stage,
    )?)?;
    Ok(())
}

fn read_project_reservation_request(
    stream: &mut std::os::unix::net::UnixStream,
    client_nonce: &[u8],
) -> Result<SourceProjectAdmissionReservationV1, Box<dyn Error>> {
    let mut bytes = [0; SOURCE_PROJECT_ADMISSION_RESERVATION_BYTES_V1];
    stream.read_exact(&mut bytes)?;
    require_stream_eof(stream)?;
    let reservation = SourceProjectAdmissionReservationV1::from_record_bytes(&bytes)
        .map_err(aos_sandbox::journal::JournalError::from)?;
    if reservation.client_nonce().as_slice() != client_nonce {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "changed Source reservation nonce",
        )
        .into());
    }
    Ok(reservation)
}

fn serve_project_negative_intent(
    stream: &mut std::os::unix::net::UnixStream,
    nonce: &[u8],
    controller_uid: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut packet = [0; CONTROLLER_PROJECT_DISPATCH_READBACK_BYTES_V1];
    stream.read_exact(&mut packet)?;
    require_stream_eof(stream)?;
    let reservation = SourceProjectAdmissionReservationV1::from_record_bytes(&packet[188..324])
        .map_err(aos_sandbox::journal::JournalError::from)?;
    let nonce: [u8; 16] = nonce.try_into()?;
    if reservation.client_nonce() != nonce {
        return Err(
            io::Error::new(io::ErrorKind::InvalidData, "changed negative intent nonce").into(),
        );
    }
    // Root obtains both historical role pins under its own protected writer.
    // The request carries no key, credential, positive input or stage authority.
    let intent = prepare_fixed_root_project_negative_intent_v1(&packet, controller_uid)?;
    stream.write_all(&encode_root_project_negative_intent_reply_v1(
        nonce, intent,
    )?)?;
    Ok(())
}

fn serve_project_intent_replay(
    stream: &mut std::os::unix::net::UnixStream,
    client_nonce: &[u8],
) -> Result<(), Box<dyn Error>> {
    let reservation = read_project_reservation_request(stream, client_nonce)?;
    let intent = recover_fixed_root_project_admission_intent_v1(reservation)?;
    stream.write_all(&encode_root_project_intent_replay_reply_v1(
        reservation,
        intent,
    )?)?;
    Ok(())
}

fn serve_project_reservation_cancel(
    stream: &mut std::os::unix::net::UnixStream,
    client_nonce: &[u8],
) -> Result<(), Box<dyn Error>> {
    let reservation = read_project_reservation_request(stream, client_nonce)?;
    let marker = cancel_fixed_root_project_reservation_v1(reservation)?;
    stream.write_all(&encode_root_project_reservation_cancel_reply_v1(
        reservation.client_nonce(),
        reservation.record_digest(),
        Some(marker),
    )?)?;
    Ok(())
}

fn serve_project_admission_abort(
    stream: &mut std::os::unix::net::UnixStream,
    client_nonce: &[u8],
    source_pin: &[u8],
    source_signer_uid: u32,
    controller_gid: u32,
) -> Result<(), Box<dyn Error>> {
    let mut stage_bytes = [0; 32];
    stream.read_exact(&mut stage_bytes)?;
    let stage_digest = ObjectDigest::from_bytes(stage_bytes);
    let mut source_bytes = [0; SOURCE_PROJECT_ADMISSION_CHALLENGE_BYTES_V1];
    stream.read_exact(&mut source_bytes)?;
    require_stream_eof(stream)?;
    let source_row = SourceProjectAdmissionChallengeV1::from_record_bytes(&source_bytes)
        .map_err(aos_sandbox::journal::JournalError::from)?;
    let stage = recover_fixed_root_project_admission_stage_v1(stage_digest)?;
    if source_row.project() != stage.project()
        || source_row.nonce() != stage.root_nonce()
        || source_row.cut() != stage.cut()
        || source_row.stage() != stage_digest
    {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "changed Source challenge").into());
    }

    let signer = PinnedSourceHoldReadbackSignerV1::decode(source_pin)?;
    let challenge = SourceHoldReadbackChallengeV1::new(stage.root_nonce(), stage.cut())?;
    let source_packet = request_root_source_project_retirement_readback_v1(
        challenge,
        source_row,
        stage.source_reservation_digest(),
        &signer,
        source_signer_uid,
        controller_gid,
    )?;
    let outcome = abort_fixed_root_project_admission_v1(
        stage_digest,
        &source_bytes,
        &source_packet,
        source_pin,
    )?;
    let nonce: [u8; 16] = client_nonce.try_into()?;
    stream.write_all(&encode_root_project_admission_terminal_reply_v1(
        nonce, outcome,
    )?)?;
    Ok(())
}

fn require_stream_eof(stream: &mut std::os::unix::net::UnixStream) -> io::Result<()> {
    let mut trailing = [0];
    if stream.read(&mut trailing)? != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "trailing project admission data",
        ));
    }
    Ok(())
}

fn serve_root_v8_terminal(
    stream: &mut std::os::unix::net::UnixStream,
    client_nonce: &[u8],
    controller_uid: u32,
) -> Result<(), Box<dyn Error>> {
    let (binding, epoch) = read_held_root_ack_claim(stream, false)?;
    let nonce: [u8; 16] = client_nonce.try_into()?;
    let credential = read_optional_pin(Path::new(CREDENTIAL_ROOT), "controller-hold-public-key")?
        .ok_or_else(|| {
        io::Error::new(io::ErrorKind::PermissionDenied, "Controller pin absent")
    })?;
    stream.set_read_timeout(Some(Duration::from_secs(35)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    let terminal = acknowledge_and_verify_fixed_closed_root_v8_terminal_v1(
        binding,
        epoch,
        controller_uid,
        &credential,
        |step| exchange_root_v8_terminal_step(stream, step, nonce, binding, epoch, false),
    )?;
    stream.write_all(&encode_root_v8_terminal_reply(
        nonce,
        binding,
        epoch,
        Some(terminal.ack()),
    )?)?;
    Ok(())
}

fn serve_root_v8_terminal_release(
    stream: &mut std::os::unix::net::UnixStream,
    client_nonce: &[u8],
    controller_uid: u32,
) -> Result<(), Box<dyn Error>> {
    let (binding, epoch) = read_held_root_ack_claim(stream, false)?;
    let nonce: [u8; 16] = client_nonce.try_into()?;
    let credential = read_optional_pin(Path::new(CREDENTIAL_ROOT), "controller-hold-public-key")?
        .ok_or_else(|| {
        io::Error::new(io::ErrorKind::PermissionDenied, "Controller pin absent")
    })?;
    stream.set_read_timeout(Some(Duration::from_secs(90)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    let custody = acknowledge_verify_and_release_fixed_closed_root_v8_terminal_v1(
        binding,
        epoch,
        controller_uid,
        &credential,
        |step| exchange_root_v8_terminal_step(stream, step, nonce, binding, epoch, true),
    )?;
    stream.write_all(&encode_root_v8_release_reply(
        nonce,
        binding,
        epoch,
        Some(custody),
    )?)?;
    Ok(())
}

fn exchange_root_v8_terminal_step(
    stream: &mut std::os::unix::net::UnixStream,
    step: RootV8HeldTerminalStepV1,
    nonce: [u8; 16],
    binding: ObjectDigest,
    epoch: u64,
    release: bool,
) -> io::Result<Vec<u8>> {
    match step {
        RootV8HeldTerminalStepV1::EffectAck(challenge) => {
            write_root_v8_terminal_challenge(
                stream,
                ROOT_V8_TERMINAL_ACK_CHALLENGE_MAGIC,
                nonce,
                challenge,
            )?;
            read_root_terminal_submission::<ROOT_V8_ACK_SUBMIT_FRAME_BYTES>(
                stream,
                nonce,
                ROOT_V8_TERMINAL_ACK_SUBMIT_MAGIC,
                false,
            )
        }
        RootV8HeldTerminalStepV1::Acknowledged(ack) => {
            stream.write_all(&encode_root_v8_terminal_stage_ack(
                nonce, binding, epoch, ack,
            )?)?;
            Ok(Vec::new())
        }
        RootV8HeldTerminalStepV1::RootReceipt(challenge) => {
            write_root_v8_terminal_challenge(
                stream,
                ROOT_V8_TERMINAL_RECEIPT_CHALLENGE_MAGIC,
                nonce,
                challenge,
            )?;
            read_root_terminal_submission::<ROOT_V8_TERMINAL_RECEIPT_SUBMIT_FRAME_BYTES>(
                stream,
                nonce,
                ROOT_V8_TERMINAL_RECEIPT_SUBMIT_MAGIC,
                !release,
            )
        }
        RootV8HeldTerminalStepV1::FinalRelease {
            challenge,
            terminal_digest,
            terminal,
        } if release => {
            if terminal_digest != terminal.record_digest() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "changed Root terminal digest",
                ));
            }
            stream.write_all(&encode_root_v8_release_stage(
                nonce, binding, epoch, terminal,
            )?)?;
            write_root_v8_terminal_challenge(
                stream,
                ROOT_V8_RELEASE_CHALLENGE_MAGIC,
                nonce,
                challenge,
            )?;
            read_root_terminal_submission::<ROOT_V8_RELEASE_SUBMIT_FRAME_BYTES>(
                stream,
                nonce,
                ROOT_V8_RELEASE_SUBMIT_MAGIC,
                true,
            )
        }
        RootV8HeldTerminalStepV1::FinalRelease { .. } => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "release step on held-only Root socket",
        )),
    }
}

fn write_root_v8_terminal_challenge(
    stream: &mut std::os::unix::net::UnixStream,
    magic: &[u8; 8],
    nonce: [u8; 16],
    challenge: ControllerEffectAckChallengeV1,
) -> io::Result<()> {
    let mut frame = [0; ROOT_V8_ACK_CHALLENGE_FRAME_BYTES];
    frame[..8].copy_from_slice(magic);
    frame[8..24].copy_from_slice(&nonce);
    frame[24..40].copy_from_slice(&challenge.nonce());
    frame[40..72].copy_from_slice(challenge.cut().as_bytes());
    stream.write_all(&frame)
}

fn read_root_terminal_submission<const N: usize>(
    stream: &mut std::os::unix::net::UnixStream,
    nonce: [u8; 16],
    magic: &[u8; 8],
    require_end: bool,
) -> io::Result<Vec<u8>> {
    read_root_submission::<N>(
        stream,
        nonce,
        magic,
        require_end,
        "invalid held Controller receipt",
    )
}

fn read_root_ack_submission<const N: usize>(
    stream: &mut std::os::unix::net::UnixStream,
    nonce: [u8; 16],
    magic: &[u8; 8],
) -> io::Result<Vec<u8>> {
    read_root_submission::<N>(stream, nonce, magic, true, "invalid Controller ACK receipt")
}

fn read_root_submission<const N: usize>(
    stream: &mut std::os::unix::net::UnixStream,
    nonce: [u8; 16],
    magic: &[u8; 8],
    require_end: bool,
    invalid_message: &'static str,
) -> io::Result<Vec<u8>> {
    let mut frame = [0; N];
    stream.read_exact(&mut frame)?;
    if &frame[..8] != magic || frame[8..24] != nonce {
        return Err(io::Error::new(io::ErrorKind::InvalidData, invalid_message));
    }
    if require_end {
        let mut trailing = [0];
        if stream.read(&mut trailing)? != 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, invalid_message));
        }
    }
    Ok(frame[24..].to_vec())
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
    explicit: Option<(&'a [u8], &'a [u8])>,
) -> io::Result<(&'a [u8], &'a [u8])> {
    match mode {
        HeadRequestMode::ClosedBinding
        | HeadRequestMode::ClosedBindingStage
        | HeadRequestMode::ClosedBindingPreview
        | HeadRequestMode::ClosedBindingSourceTerminalReplay
        | HeadRequestMode::StagedCacheSigner => explicit.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "explicit project source is unavailable",
            )
        }),
        HeadRequestMode::SourceGenesis
        | HeadRequestMode::SourceResourceGlobalGenesis
        | HeadRequestMode::SourceFirstSuccessor
        | HeadRequestMode::SourceProjectGenesis
        | HeadRequestMode::SourceProjectSuccessor
        | HeadRequestMode::CreateQ04
        | HeadRequestMode::ConsumerReadPreRoot
        | HeadRequestMode::GitEvidenceView
        | HeadRequestMode::GitCoverageEnrollment
        | HeadRequestMode::ClosedBindingReplay
        | HeadRequestMode::RootV8EffectAck
        | HeadRequestMode::RootV8EffectAckReplay
        | HeadRequestMode::RootV8Terminal
        | HeadRequestMode::RootV8TerminalReplay
        | HeadRequestMode::RootV8TerminalRelease
        | HeadRequestMode::RootV8TerminalReleaseReplay
        | HeadRequestMode::RootV8SettledGrant
        | HeadRequestMode::ProjectAdmissionOutcomeReplay
        | HeadRequestMode::ProjectAdmissionIntent
        | HeadRequestMode::ProjectNegativeIntent
        | HeadRequestMode::ProjectAdmissionIntentReplay
        | HeadRequestMode::ProjectAdmissionStage
        | HeadRequestMode::ProjectAdmissionCommit
        | HeadRequestMode::ProjectAdmissionAbort
        | HeadRequestMode::ProjectAdmissionCurrentStage
        | HeadRequestMode::ProjectReservationCancel
        | HeadRequestMode::ProjectReservationCancelReplay
        | HeadRequestMode::ProjectHistoryFloorReplay
        | HeadRequestMode::ProjectHistoryRetirement
        | HeadRequestMode::ClosedBindingSourceCasReplay => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "held Q04 recovery has no project source",
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::os::unix::net::UnixStream;

    use super::*;

    #[test]
    fn pre_root_alone_defers_root_gate_but_cannot_use_legacy_or_recovery() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let mut request = [0; REQUEST_BYTES];
        request[..8].copy_from_slice(
            aos_sandbox::policy_compiler::consumer_read_flight::CONSUMER_READ_BOOTSTRAP_MAGIC_V1,
        );
        request[8..24].fill(1);
        request[24..].copy_from_slice(&100_u64.to_be_bytes());
        client.write_all(&request).unwrap();
        let gates = Cell::new(0);
        let (actual, mode) = read_head_request(&mut server, || {
            gates.set(gates.get() + 1);
            Ok(())
        })
        .unwrap();
        assert_eq!(actual, request);
        assert!(matches!(mode, HeadRequestMode::ConsumerReadPreRoot));
        assert_eq!(gates.get(), 0);
        assert!(require_pre_root_startup(None).is_err());
        assert!(!project_recovery_mode_allowed(mode));
        assert!(select_project_source(mode, None).is_err());
        for offset in [8, 24] {
            let (mut client, mut server) = UnixStream::pair().unwrap();
            let mut malformed = request;
            malformed[offset..if offset == 8 { 24 } else { 32 }].fill(0);
            client.write_all(&malformed).unwrap();
            assert!(
                read_head_request(&mut server, || panic!(
                    "malformed bootstrap must not open Root"
                ))
                .is_err()
            );
        }
        let (mut client, mut server) = UnixStream::pair().unwrap();
        client.write_all(&request).unwrap();
        assert!(read_cache_signer_recovery_header(&mut server).is_err());
    }

    #[test]
    fn genesis_query_is_nonce_bound_and_requires_root_custody_gate() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let mut request = [0; REQUEST_BYTES];
        request[..8].copy_from_slice(ROOT_SOURCE_GENESIS_QUERY_MAGIC_V1);
        request[8..24].copy_from_slice(&[1; 16]);
        client.write_all(&request).unwrap();
        let gates = Cell::new(0);

        let (_, mode) = read_head_request(&mut server, || {
            gates.set(gates.get() + 1);
            Ok(())
        })
        .unwrap();

        assert!(matches!(mode, HeadRequestMode::SourceGenesis));
        assert_eq!(gates.get(), 1);
        assert!(project_recovery_mode_allowed(mode));
        assert!(select_project_source(mode, None).is_err());
    }

    #[test]
    fn malformed_genesis_query_refuses_before_root_custody() {
        for malformed in [false, true] {
            let (mut client, mut server) = UnixStream::pair().unwrap();
            let mut request = [0; REQUEST_BYTES];
            request[..8].copy_from_slice(ROOT_SOURCE_GENESIS_QUERY_MAGIC_V1);
            if malformed {
                request[8..24].copy_from_slice(&[1; 16]);
                request[31] = 1;
            }
            client.write_all(&request).unwrap();
            let gates = Cell::new(0);

            assert!(
                read_head_request(&mut server, || {
                    gates.set(gates.get() + 1);
                    Ok(())
                })
                .is_err()
            );
            assert_eq!(gates.get(), 0);
        }
    }

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
        for nonce in [[1; 16], [0; 16]] {
            let directory = tempfile::tempdir().expect("root journal fixture");
            let journal_path = directory.path().join("policy-authority.journal");
            std::fs::write(&journal_path, b"root journal before request")
                .expect("root journal fixture");
            let (mut client, mut server) = UnixStream::pair().expect("local policy socket");
            let mut request = [0_u8; REQUEST_BYTES];
            request[..8].copy_from_slice(POLICY_BINDING_QUERY_MAGIC_V4);
            request[8..24].copy_from_slice(&nonce);
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
    }

    #[test]
    fn retired_source_flight_queries_refuse_before_root_custody() {
        for magic in [
            b"AOSPHQ4F", b"AOSPHQ5F", b"AOSPHQ6F", b"AOSPHQ7F", b"AOSPHQ8F",
        ] {
            for nonce in [[7; 16], [0; 16]] {
                let (mut client, mut server) = UnixStream::pair().expect("local policy socket");
                let mut request = [0; REQUEST_BYTES];
                request[..8].copy_from_slice(magic);
                request[8..24].copy_from_slice(&nonce);
                client.write_all(&request).expect("retired flight query");

                let custody_calls = Cell::new(0);
                let error = read_head_request(&mut server, || {
                    custody_calls.set(custody_calls.get() + 1);
                    Ok(())
                })
                .err()
                .expect("retired purpose must fail at parsing");

                assert_eq!(error.to_string(), "invalid head query");
                assert_eq!(custody_calls.get(), 0);
            }
        }
    }

    #[test]
    fn marked_q04_query_refuses_before_root_custody() {
        for nonce in [[7; 16], [0; 16]] {
            for marker in [*b"AOSQ4H01", *b"AOSQ4H02"] {
                let (mut client, mut server) = UnixStream::pair().expect("local policy socket");
                let mut request = [0; REQUEST_BYTES];
                request[..8].copy_from_slice(POLICY_BINDING_QUERY_MAGIC_V4);
                request[8..24].copy_from_slice(&nonce);
                request[24..].copy_from_slice(&marker);
                client.write_all(&request).expect("retired marked query");

                let opened = Cell::new(false);
                assert!(
                    read_head_request(&mut server, || {
                        opened.set(true);
                        Ok(())
                    })
                    .is_err()
                );
                assert!(!opened.get());

                drop(server);
                let mut response = Vec::new();
                client.read_to_end(&mut response).expect("refused response");
                assert!(response.is_empty());
            }
        }
    }

    #[test]
    fn v7_historical_replay_keeps_nonce_and_exact_digest_claim() {
        for (nonce, gate_available) in [
            ([7; 16], true),
            ([7; 16], false),
            ([0; 16], true),
            ([0; 16], false),
        ] {
            let (mut client, mut server) = UnixStream::pair().expect("local socket");
            let mut request = [0; REQUEST_BYTES];
            request[..8].copy_from_slice(POLICY_BINDING_SOURCE_FLIGHT_REPLAY_QUERY_MAGIC_V7);
            request[8..24].copy_from_slice(&nonce);
            client.write_all(&request).expect("V7 historical query");

            let opened = Cell::new(false);
            let result = read_head_request(&mut server, || {
                opened.set(true);
                if gate_available {
                    Ok(())
                } else {
                    Err(io::Error::new(io::ErrorKind::PermissionDenied, "held Root CAS").into())
                }
            });
            if nonce == [0; 16] {
                assert!(result.is_err());
                assert!(!opened.get());
            } else if gate_available {
                assert!(matches!(
                    result.expect("historical replay").1,
                    HeadRequestMode::ClosedBindingSourceTerminalReplay
                ));
                assert!(opened.get());
            } else {
                assert_eq!(
                    result.err().expect("held gate refuses").to_string(),
                    "held Root CAS"
                );
                assert!(opened.get());
            }
        }

        for (digest, length, trailing, valid) in [
            ([9; 32], 32, false, true),
            ([0; 32], 32, false, false),
            ([9; 32], 31, false, false),
            ([9; 32], 32, true, false),
        ] {
            let (mut client, mut server) = UnixStream::pair().expect("local socket");
            client.write_all(&digest[..length]).expect("replay digest");
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
    fn v8_replay_keeps_root_ack_dispatch_and_exact_legacy_receipt() {
        // This legacy magic aliases the earlier Root ACK replay discriminator.
        // The legacy receipt below is a separate format check.
        assert_eq!(
            POLICY_BINDING_SOURCE_FLIGHT_REPLAY_QUERY_MAGIC_V8,
            ROOT_V8_ACK_REPLAY_QUERY_MAGIC,
        );
        let nonce = [17; 16];
        for (query_nonce, reserved, valid) in [
            (nonce, 0, true),
            ([0; 16], 0, false),
            (nonce, 1, false),
        ] {
            let (mut client, mut server) = UnixStream::pair().expect("V8 replay pair");
            let mut request = [0; REQUEST_BYTES];
            request[..8].copy_from_slice(POLICY_BINDING_SOURCE_FLIGHT_REPLAY_QUERY_MAGIC_V8);
            request[8..24].copy_from_slice(&query_nonce);
            request[24] = reserved;
            client.write_all(&request).expect("V8 replay query");

            let opened = Cell::new(false);
            let result = read_head_request(&mut server, || {
                opened.set(true);
                Err(io::Error::new(io::ErrorKind::PermissionDenied, "held Root CAS").into())
            });
            if valid {
                assert!(matches!(
                    result.expect("Root ACK replay").1,
                    HeadRequestMode::RootV8EffectAckReplay
                ));
            } else {
                assert!(result.is_err());
            }
            assert!(!opened.get());
        }

        let (mut client, mut server) = UnixStream::pair().expect("V8 receipt pair");
        write_closed_source_cas_receipt_v8(
            &mut server,
            POLICY_BINDING_SOURCE_FLIGHT_REPLAY_REPLY_MAGIC_V8,
            &nonce,
            ObjectDigest::from_bytes([1; 32]),
            4,
            ObjectDigest::from_bytes([2; 32]),
            ObjectDigest::from_bytes([3; 32]),
            ObjectDigest::from_bytes([4; 32]),
        )
        .expect("historical receipt");
        let mut receipt = [0; 160];
        client.read_exact(&mut receipt).expect("complete receipt");
        assert_eq!(&receipt[..8], POLICY_BINDING_SOURCE_FLIGHT_REPLAY_REPLY_MAGIC_V8);
        assert_eq!(&receipt[8..24], &nonce);
        assert_eq!(&receipt[24..56], &[1; 32]);
        assert_eq!(&receipt[56..64], &4_u64.to_be_bytes());
        assert_eq!(&receipt[64..96], &[2; 32]);
        assert_eq!(&receipt[96..128], &[3; 32]);
        assert_eq!(&receipt[128..], &[4; 32]);
        assert!(
            write_closed_source_cas_receipt_v8(
                &mut server,
                POLICY_BINDING_SOURCE_FLIGHT_REPLAY_REPLY_MAGIC_V8,
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
    fn retired_root_ack_headers_refuse_before_custody_callback() {
        for magic in [b"AOSPHQ6A", b"AOSPHQ6R"] {
            for (nonce, reserved) in [(7, 0), (0, 0), (7, 1)] {
                let (mut client, mut server) = UnixStream::pair().unwrap();
                let mut request = [0; REQUEST_BYTES];
                request[..8].copy_from_slice(magic);
                request[8..24].fill(nonce);
                request[24] = reserved;
                client.write_all(&request).unwrap();

                let gate_opened = Cell::new(false);
                let error = read_head_request(&mut server, || {
                    gate_opened.set(true);
                    Ok(())
                })
                .err()
                .expect("retired header");
                let error = error
                    .downcast_ref::<io::Error>()
                    .expect("original I/O refusal");

                assert_eq!(error.kind(), io::ErrorKind::InvalidData);
                assert_eq!(error.to_string(), "invalid head query");
                assert!(!gate_opened.get());
            }
        }
    }

    #[test]
    fn root_effect_ack_headers_keep_the_held_gate_closed_for_other_modes() {
        for magic in [
            ROOT_V8_ACK_QUERY_MAGIC,
            ROOT_V8_ACK_REPLAY_QUERY_MAGIC,
            ROOT_V8_TERMINAL_QUERY_MAGIC,
            ROOT_V8_TERMINAL_REPLAY_QUERY_MAGIC,
            ROOT_V8_RELEASE_QUERY_MAGIC,
            ROOT_V8_RELEASE_REPLAY_QUERY_MAGIC,
            ROOT_V8_SETTLED_QUERY_MAGIC,
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
                HeadRequestMode::RootV8EffectAck
                    | HeadRequestMode::RootV8EffectAckReplay
                    | HeadRequestMode::RootV8Terminal
                    | HeadRequestMode::RootV8TerminalReplay
                    | HeadRequestMode::RootV8TerminalRelease
                    | HeadRequestMode::RootV8TerminalReleaseReplay
                    | HeadRequestMode::RootV8SettledGrant
            ));

            request[8..24].fill(0);
            let (mut client, mut server) = UnixStream::pair().expect("local Root ACK socket");
            client.write_all(&request).expect("zero Root ACK nonce");
            assert!(read_head_request(&mut server, || Ok(())).is_err());
        }

        let (mut client, mut server) = UnixStream::pair().expect("local Root grant socket");
        let mut request = [0; REQUEST_BYTES];
        request[..8].copy_from_slice(ROOT_V8_SETTLED_QUERY_MAGIC);
        request[8..24].fill(7);
        request[24] = 1;
        client
            .write_all(&request)
            .expect("reserved Root grant query");
        assert!(read_head_request(&mut server, || Ok(())).is_err());
    }

    #[test]
    fn held_v8_terminal_submission_keeps_first_stage_open_and_bounds_final_stage() {
        let nonce = [7; 16];
        let mut ack = [0; ROOT_V8_ACK_SUBMIT_FRAME_BYTES];
        ack[..8].copy_from_slice(ROOT_V8_TERMINAL_ACK_SUBMIT_MAGIC);
        ack[8..24].copy_from_slice(&nonce);
        ack[24..].fill(9);
        let (mut client, mut root) = UnixStream::pair().unwrap();
        client.write_all(&ack).unwrap();
        assert_eq!(
            read_root_terminal_submission::<ROOT_V8_ACK_SUBMIT_FRAME_BYTES>(
                &mut root,
                nonce,
                ROOT_V8_TERMINAL_ACK_SUBMIT_MAGIC,
                false,
            )
            .unwrap(),
            vec![9; ack.len() - 24]
        );

        let mut receipt = [0; ROOT_V8_TERMINAL_RECEIPT_SUBMIT_FRAME_BYTES];
        receipt[..8].copy_from_slice(ROOT_V8_TERMINAL_RECEIPT_SUBMIT_MAGIC);
        receipt[8..24].copy_from_slice(&nonce);
        receipt[24..].fill(10);
        client.write_all(&receipt).unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        assert_eq!(
            read_root_terminal_submission::<ROOT_V8_TERMINAL_RECEIPT_SUBMIT_FRAME_BYTES>(
                &mut root,
                nonce,
                ROOT_V8_TERMINAL_RECEIPT_SUBMIT_MAGIC,
                true,
            )
            .unwrap(),
            vec![10; receipt.len() - 24]
        );

        let (mut client, mut root) = UnixStream::pair().unwrap();
        client.write_all(&receipt).unwrap();
        client.write_all(&[1]).unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        assert!(
            read_root_terminal_submission::<ROOT_V8_TERMINAL_RECEIPT_SUBMIT_FRAME_BYTES>(
                &mut root,
                nonce,
                ROOT_V8_TERMINAL_RECEIPT_SUBMIT_MAGIC,
                true,
            )
            .is_err()
        );
    }

    #[test]
    fn held_v8_release_submission_requires_exact_magic_nonce_and_eof() {
        let nonce = [7; 16];
        let mut frame = [0; ROOT_V8_RELEASE_SUBMIT_FRAME_BYTES];
        frame[..8].copy_from_slice(ROOT_V8_RELEASE_SUBMIT_MAGIC);
        frame[8..24].copy_from_slice(&nonce);
        frame[24..].fill(9);
        let read = |bytes: &[u8], nonce| {
            let (mut client, mut root) = UnixStream::pair().unwrap();
            client.write_all(bytes).unwrap();
            client.shutdown(std::net::Shutdown::Write).unwrap();
            read_root_terminal_submission::<ROOT_V8_RELEASE_SUBMIT_FRAME_BYTES>(
                &mut root,
                nonce,
                ROOT_V8_RELEASE_SUBMIT_MAGIC,
                true,
            )
        };

        assert_eq!(read(&frame, nonce).unwrap(), vec![9; frame.len() - 24]);
        assert!(read(&frame, [8; 16]).is_err());
        let mut foreign = frame;
        foreign[..8].copy_from_slice(ROOT_V8_TERMINAL_RECEIPT_SUBMIT_MAGIC);
        assert!(read(&foreign, nonce).is_err());
        assert!(read(&frame[..frame.len() - 1], nonce).is_err());
        assert!(read(&[frame.as_slice(), &[1]].concat(), nonce).is_err());
    }

    #[test]
    fn v8_root_ack_submission_rejects_wrong_role_truncation_and_trailing_bytes() {
        let mut frame = [0; ROOT_V8_ACK_SUBMIT_FRAME_BYTES];
        frame[..8].copy_from_slice(ROOT_V8_ACK_SUBMIT_MAGIC);
        frame[8..24].fill(7);
        frame[24..].fill(9);
        let read = |bytes: &[u8], nonce| {
            let (mut client, mut server) = UnixStream::pair().expect("local V8 ACK submission");
            client.write_all(bytes).expect("V8 ACK bytes");
            client
                .shutdown(std::net::Shutdown::Write)
                .expect("V8 ACK EOF");
            server
                .set_read_timeout(Some(Duration::from_millis(20)))
                .unwrap();
            read_root_v8_effect_ack_submission(&mut server, nonce)
        };
        assert_eq!(
            read(&frame, [7; 16]).unwrap(),
            vec![9; aos_sandbox::policy_compiler::CONTROLLER_V8_EFFECT_ACK_READBACK_BYTES_V1]
        );
        assert!(read(&frame, [8; 16]).is_err());
        let mut old_role = frame;
        old_role[..8].copy_from_slice(b"AOSPHS6A");
        assert!(read(&old_role, [7; 16]).is_err());
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
            read_held_root_ack_claim(&mut server, replay)
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
    fn project_reservation_cancel_and_replay_have_distinct_root_custody_modes() {
        for (magic, expected, opens_root) in [
            (
                ROOT_PROJECT_RESERVATION_CANCEL_MAGIC,
                HeadRequestMode::ProjectReservationCancel,
                true,
            ),
            (
                ROOT_PROJECT_RESERVATION_CANCEL_QUERY_MAGIC,
                HeadRequestMode::ProjectReservationCancelReplay,
                false,
            ),
        ] {
            let (mut client, mut server) = UnixStream::pair().expect("local policy socket");
            let mut request = [0_u8; REQUEST_BYTES];
            request[..8].copy_from_slice(magic);
            request[8..24].copy_from_slice(&[1; 16]);
            client
                .write_all(&request)
                .expect("project cancellation header");
            let root_custody_opened = Cell::new(false);
            let (_, mode) = read_head_request(&mut server, || {
                root_custody_opened.set(true);
                Ok(())
            })
            .expect("distinct project cancellation mode");
            assert!(std::mem::discriminant(&mode) == std::mem::discriminant(&expected));
            assert_eq!(root_custody_opened.get(), opens_root);
        }
    }

    #[test]
    fn project_history_headers_separate_readback_and_retirement_custody() {
        for (magic, expected, opens_root) in [
            (
                ROOT_PROJECT_NEGATIVE_INTENT_QUERY_MAGIC,
                HeadRequestMode::ProjectNegativeIntent,
                true,
            ),
            (
                ROOT_PROJECT_HISTORY_FLOOR_QUERY_MAGIC,
                HeadRequestMode::ProjectHistoryFloorReplay,
                false,
            ),
            (
                ROOT_PROJECT_HISTORY_RETIRE_MAGIC,
                HeadRequestMode::ProjectHistoryRetirement,
                true,
            ),
        ] {
            let read = |nonce: [u8; 16], reserved: u8| {
                let (mut client, mut server) = UnixStream::pair().unwrap();
                let mut request = [0; REQUEST_BYTES];
                request[..8].copy_from_slice(magic);
                request[8..24].copy_from_slice(&nonce);
                request[24] = reserved;
                client.write_all(&request).unwrap();
                let opened = Cell::new(false);
                let result = read_head_request(&mut server, || {
                    opened.set(true);
                    Ok(())
                });
                (result, opened.get())
            };
            let (result, opened) = read([1; 16], 0);
            let (_, mode) = result.unwrap();
            assert!(std::mem::discriminant(&mode) == std::mem::discriminant(&expected));
            assert_eq!(opened, opens_root);
            for (nonce, reserved) in [([0; 16], 0), ([1; 16], 1)] {
                let (result, opened) = read(nonce, reserved);
                assert!(result.is_err());
                assert!(!opened);
            }
        }
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let mut request = [0; REQUEST_BYTES];
        request[..8].copy_from_slice(b"AOSPHIQ2");
        request[8..24].fill(1);
        client.write_all(&request).unwrap();
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

    #[test]
    fn project_recovery_only_rejects_fresh_authority_before_root_custody() {
        for magic in [
            ROOT_PROJECT_ADMISSION_INTENT_QUERY_MAGIC,
            ROOT_PROJECT_ADMISSION_STAGE_QUERY_MAGIC,
            ROOT_PROJECT_ADMISSION_COMMIT_QUERY_MAGIC,
        ] {
            let (mut client, mut server) = UnixStream::pair().expect("local Root recovery socket");
            let mut request = [0; REQUEST_BYTES];
            request[..8].copy_from_slice(magic);
            request[8..24].fill(1);
            client.write_all(&request).unwrap();
            client.shutdown(std::net::Shutdown::Write).unwrap();

            let uid = rustix::process::getuid().as_raw();
            let gid = rustix::process::getgid().as_raw();
            let error = serve_project_admission_recovery_request(&mut server, uid, gid, uid, None)
                .expect_err("expired credentials cannot mint fresh Root authority");
            assert!(error.to_string().contains("recovery-only Root"));
        }
        for mode in [
            HeadRequestMode::ProjectNegativeIntent,
            HeadRequestMode::ProjectHistoryFloorReplay,
            HeadRequestMode::ProjectHistoryRetirement,
            HeadRequestMode::ProjectAdmissionOutcomeReplay,
            HeadRequestMode::ProjectAdmissionCurrentStage,
            HeadRequestMode::ProjectReservationCancelReplay,
            HeadRequestMode::ProjectAdmissionIntentReplay,
            HeadRequestMode::ProjectReservationCancel,
            HeadRequestMode::ProjectAdmissionAbort,
        ] {
            assert!(project_recovery_mode_allowed(mode));
        }
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
    fn retired_queries_are_refused_before_root_custody() {
        for magic in [b"AOSPHQ05", b"AOSPHQ02", b"AOSPHQ03"] {
            let (mut client, mut server) = UnixStream::pair().expect("local policy socket");
            let mut request = [0_u8; REQUEST_BYTES];
            request[..8].copy_from_slice(magic);
            request[8..24].copy_from_slice(&[1; 16]);
            client.write_all(&request).expect("retired query");
            let root_custody_opened = Cell::new(false);

            let returned = read_head_request(&mut server, || {
                root_custody_opened.set(true);
                Ok(())
            });

            let error = returned.err().expect("retired query refused");
            let native = error
                .downcast_ref::<io::Error>()
                .expect("native query cause");
            assert_eq!(native.kind(), io::ErrorKind::InvalidData);
            assert_eq!(native.to_string(), "invalid head query");
            assert!(!root_custody_opened.get());
        }
    }

    #[test]
    fn read_only_and_cache_request_modes_reach_root_custody_gate() {
        for magic in [
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
        submission[..8].copy_from_slice(b"AOSPHR05");
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
    fn project_source_modes_require_the_current_credentials() {
        let error = require_explicit_project_source(false).expect_err("missing current source");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "exactly one project source version is required"
        );
        assert!(require_explicit_project_source(true).is_ok());

        let explicit = Some((b"explicit-packet".as_slice(), b"explicit-input".as_slice()));
        assert!(select_project_source(HeadRequestMode::ClosedBinding, None).is_err());
        assert!(select_project_source(HeadRequestMode::StagedCacheSigner, None).is_err());
        assert_eq!(
            select_project_source(HeadRequestMode::ClosedBinding, explicit)
                .expect("explicit source")
                .0,
            b"explicit-packet"
        );
        assert_eq!(
            select_project_source(HeadRequestMode::StagedCacheSigner, explicit)
                .expect("explicit source")
                .0,
            b"explicit-packet"
        );
        assert_eq!(
            select_project_source(HeadRequestMode::StagedCacheSigner, explicit)
                .expect("explicit source")
                .0,
            b"explicit-packet"
        );
    }

    #[test]
    fn retired_project_credentials_refuse_every_present_name() {
        let directory = tempfile::tempdir().expect("credential directory");
        require_no_retired_project_credentials(directory.path()).expect("retired names absent");
        std::fs::write(directory.path().join("project-head-v2.packet"), [1; 328])
            .expect("current packet");
        std::fs::write(directory.path().join("project-layer-v2.json"), b"input")
            .expect("current input");

        for name in ["project-head.packet", "project-layer.json"] {
            let path = directory.path().join(name);
            std::fs::write(&path, b"not a supported credential").expect("retired name");
            let error = require_no_retired_project_credentials(directory.path())
                .expect_err("partial retired pair refused even with current pair");
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            std::fs::remove_file(&path).expect("remove retired file");

            std::os::unix::fs::symlink("missing-target", &path).expect("dangling retired symlink");
            assert!(require_no_retired_project_credentials(directory.path()).is_err());
            std::fs::remove_file(&path).expect("remove retired symlink");

            std::fs::create_dir(&path).expect("retired directory name");
            assert!(require_no_retired_project_credentials(directory.path()).is_err());
            std::fs::remove_dir(&path).expect("remove retired directory");
        }

        std::fs::write(directory.path().join("project-head.packet"), b"packet")
            .expect("retired packet");
        std::fs::write(directory.path().join("project-layer.json"), b"input")
            .expect("retired input");
        assert!(require_no_retired_project_credentials(directory.path()).is_err());
    }

    #[test]
    fn retired_name_check_preserves_native_metadata_failure() {
        let directory = tempfile::tempdir().expect("credential directory");
        let root = directory.path().join("not-a-directory");
        std::fs::write(&root, b"file").expect("non-directory credential root");

        let returned =
            require_no_retired_project_credentials(&root).expect_err("native metadata failure");
        let original = std::fs::symlink_metadata(root.join("project-head.packet"))
            .expect_err("same native metadata operation");

        assert_eq!(returned.kind(), original.kind());
        assert_eq!(returned.raw_os_error(), original.raw_os_error());
        assert!(returned.raw_os_error().is_some());
    }
}

fn read_bounded(path: &Path, maximum: u64) -> io::Result<Vec<u8>> {
    let file = File::open(path)?;
    let mut bytes = Vec::new();
    read_bounded_into(file, maximum, &mut bytes)?;
    Ok(bytes)
}

// Both an ordinary owned File and a selected original borrowed File use this
// same Read/size kernel. It does not grant payment or erase partial bytes.
fn read_bounded_into(
    file: impl Read,
    maximum: u64,
    bytes: &mut Vec<u8>,
) -> io::Result<()> {
    file.take(maximum + 1).read_to_end(bytes)?;
    if bytes.is_empty() || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "credential size",
        ));
    }
    Ok(())
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

// Retired credential names cannot silently select or fall back to the current profile.
fn require_no_retired_project_credentials(root: &Path) -> io::Result<()> {
    for name in ["project-head.packet", "project-layer.json"] {
        match std::fs::symlink_metadata(root.join(name)) {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "retired project source credentials are unsupported",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
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
