//! Admits externally signed deployment policy inputs under root-owned custody.
//!
//! This service commits the monotonic deployment input head and serves an
//! authenticated signed-head receipt to the node controller. Its version-4
//! exchange can retain a closed AOSPCB02 root CAS and handoff epoch. It cannot
//! admit the project source against the controller-owned publisher journal,
//! authorize compiler publication, or authorize Create effects. A separate
//! version-5 exchange spends a root challenge and verifies a Cache-only signed
//! readback without promoting it into Q04 authority.
//! Root-only recovery modes inspect or release an abandoned version-4 hold.
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

use aos_sandbox::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1;
use aos_sandbox::policy_compiler::{
    CLOSED_POLICY_BINDING_BYTES_V2, ClosedCacheReadbackRootChallengeV1, ClosedPolicyRootCasBaseV2,
    PolicyDeploymentInputsV1, admit_fixed_cache_readback_pin_v1,
    admit_fixed_controller_hold_pin_v1, admit_fixed_policy_deployment_head_v1,
    admit_fixed_policy_signer_pins_v1, decode_policy_deployment_sources_v1,
    read_fixed_inert_closed_policy_binding_hold_v1, release_fixed_closed_policy_controller_hold_v1,
    release_fixed_closed_policy_source_domain_hold_v1,
    release_fixed_inert_closed_policy_binding_hold_v1,
    require_no_fixed_closed_policy_binding_hold_v1, verify_policy_deployment_head_v1,
    verify_signed_project_policy_source_v1, verify_signed_project_policy_source_v2,
    with_fixed_closed_cache_readback_session_v1, with_fixed_current_policy_head_lease_v1,
    with_fixed_explicit_closed_policy_binding_session_v2,
};
use aos_sandbox::{Journal, controller_service::journal::production_journal_limits};
use aos_sandbox_broker_session_security::policy_authority_client::{
    POLICY_AUTHORITY_SOCKET_PATH_V2, POLICY_BINDING_ACK_MAGIC_V4, POLICY_BINDING_BASE_MAGIC_V4,
    POLICY_BINDING_COMMITTED_MAGIC_V4, POLICY_BINDING_COMPLETE_MAGIC_V4,
    POLICY_BINDING_QUERY_MAGIC_V4, POLICY_BINDING_RECEIPT_MAGIC_V4, POLICY_BINDING_SUBMIT_MAGIC_V4,
    POLICY_BINDING_TERMINAL_ACK_MAGIC_V4, POLICY_HEAD_LEASE_ACK_MAGIC_V3,
    POLICY_HEAD_LEASE_COMPLETE_MAGIC_V3, POLICY_HEAD_LEASE_QUERY_MAGIC_V3,
    POLICY_HEAD_QUERY_MAGIC_V2, POLICY_HEAD_RECEIPT_MAGIC_V2,
};
use aos_sandbox_broker_session_security::policy_cache_readback_client::{
    CLOSED_CACHE_READBACK_SUBMIT_FRAME_BYTES_V5, POLICY_CACHE_READBACK_CHALLENGE_MAGIC_V5,
    POLICY_CACHE_READBACK_OBSERVATION_MAGIC_V5, POLICY_CACHE_READBACK_QUERY_MAGIC_V5,
    POLICY_CACHE_READBACK_SUBMIT_MAGIC_V5,
};
use aos_sandbox_broker_session_security::policy_signer_credential::{
    PinnedPolicySignerV1, PolicySignerRoleV1,
};
use aos_sandbox_core::ObjectDigest;
use ed25519_dalek::VerifyingKey;

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

#[derive(Clone, Copy)]
enum HeadRequestMode {
    Query,
    Lease,
    ClosedBinding,
    ClosedCacheReadback,
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
    if controller_uid == 0 || controller_gid == 0 || arguments.next().is_some() {
        return Err(
            io::Error::new(io::ErrorKind::InvalidInput, "invalid controller identity").into(),
        );
    }

    // A lost Q04 ACK retains the root hold across restart. Resolve it from
    // protected custody before this service admits any new policy input.
    require_no_fixed_closed_policy_binding_hold_v1()?;

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

    let socket_path = Path::new(POLICY_AUTHORITY_SOCKET_PATH_V2);
    if let Ok(metadata) = socket_path.symlink_metadata() {
        if !metadata.file_type().is_socket() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "unsafe authority socket path",
            )
            .into());
        }
        std::fs::remove_file(socket_path)?;
    }
    let listener = UnixListener::bind(socket_path)?;

    for accepted in listener.incoming() {
        let mut stream = match accepted {
            Ok(stream) => stream,
            Err(error) => return Err(error.into()),
        };
        if let Err(error) = serve_current_head(
            &mut stream,
            controller_uid,
            controller_gid,
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
        ) {
            eprintln!("aos-sandbox-policy-authorityd: rejected head query: {error}");
        }
    }
    Err(io::Error::new(io::ErrorKind::BrokenPipe, "authority listener ended").into())
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
    if value.len() != 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid binding head",
        ));
    }
    let mut bytes = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = (pair[0] as char)
            .to_digit(16)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid binding head"))?;
        let low = (pair[1] as char)
            .to_digit(16)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid binding head"))?;
        bytes[index] = u8::try_from((high << 4) | low).map_err(io::Error::other)?;
    }
    if bytes == [0; 32] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "zero binding head",
        ));
    }
    Ok(ObjectDigest::from_bytes(bytes))
}

fn binding_head_hex(binding: ObjectDigest) -> String {
    let mut encoded = String::with_capacity(64);
    for byte in binding.as_bytes() {
        encoded.push_str(&format!("{byte:02x}"));
    }
    encoded
}

fn serve_current_head(
    stream: &mut std::os::unix::net::UnixStream,
    controller_uid: u32,
    controller_gid: u32,
    packet: &[u8],
    inputs: &PolicyDeploymentInputsV1<'_>,
    verifying_key: &VerifyingKey,
    deployment_signer_generation: u64,
    legacy_project: Option<(&[u8], &[u8])>,
    explicit_project: Option<(&[u8], &[u8])>,
    project_key: &VerifyingKey,
    project_signer_generation: u64,
    cache_pin: Option<&[u8]>,
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

    let mut request = [0_u8; REQUEST_BYTES];
    stream.read_exact(&mut request)?;
    let mode = match request.get(..8) {
        Some(magic) if magic == POLICY_HEAD_QUERY_MAGIC_V2 => HeadRequestMode::Query,
        Some(magic) if magic == POLICY_HEAD_LEASE_QUERY_MAGIC_V3 => HeadRequestMode::Lease,
        Some(magic) if magic == POLICY_BINDING_QUERY_MAGIC_V4 => HeadRequestMode::ClosedBinding,
        Some(magic) if magic == POLICY_CACHE_READBACK_QUERY_MAGIC_V5 => {
            HeadRequestMode::ClosedCacheReadback
        }
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid head query").into()),
    };
    if request[24..] != [0; 8] {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid head query").into());
    }
    require_no_fixed_closed_policy_binding_hold_v1()?;
    if matches!(mode, HeadRequestMode::ClosedCacheReadback) && request[8..24] == [0; 16] {
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
        HeadRequestMode::ClosedBinding | HeadRequestMode::ClosedCacheReadback
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

fn select_project_source<'a>(
    mode: HeadRequestMode,
    legacy: Option<(&'a [u8], &'a [u8])>,
    explicit: Option<(&'a [u8], &'a [u8])>,
) -> io::Result<(&'a [u8], &'a [u8])> {
    match mode {
        HeadRequestMode::ClosedBinding | HeadRequestMode::ClosedCacheReadback => explicit
            .ok_or_else(|| {
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
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::io::Cursor;

    use super::*;

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
