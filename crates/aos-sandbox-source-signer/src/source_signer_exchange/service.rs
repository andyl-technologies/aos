//! Fixed activation and request dispatch for the independent Source signer.
//!
//! This private owner retains the startup credential, inherited listener and
//! complete per-request signing, peer checks, send and shutdown recipes.
//! The parent owns Root client verification and shared canonical wire framing.
//! Source16 remains refused before key access or native observation; its
//! separate retained CurrentNix owner is unchanged.
//!
//! This grouping preserves service custody without changing dependency or
//! production authority boundaries.

use std::error::Error;
use std::io::{self, Read as _};
use std::os::fd::AsFd as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

use aos_sandbox::policy_compiler::{
    RootFirstSourceSuccessorIntentV2, sign_fixed_source_first_successor_readback_v2,
    sign_fixed_source_project_admission_readback_v1,
    sign_fixed_source_project_completed_terminal_readback_v1,
    sign_fixed_source_project_continuation_readback_v3,
    sign_fixed_source_project_genesis_readback_v4,
    sign_fixed_source_project_reservation_readback_v1,
    sign_fixed_source_project_retirement_readback_v1, sign_fixed_source_signer_readback_v1,
    sign_fixed_source_signer_readback_v2, sign_fixed_source_tree_genesis_readback_v2,
    sign_fixed_source_tree_genesis_readback_v3,
};
use rustix::net::sockopt::{socket_acceptconn, socket_peercred};

use crate::source_signer_credential::SourceSignerCredentialV1;

use super::{
    FLIGHT_TIMEOUT, REPLY_BYTES, REPLY_COMPLETED_BYTES, REPLY_COMPLETED_MAGIC,
    REPLY_FIRST_SUCCESSOR_BYTES, REPLY_GENESIS_BYTES, REPLY_GENESIS_MAGIC, REPLY_MAGIC,
    REPLY_NAMES_BYTES, REPLY_NAMES_MAGIC, REPLY_PROJECT_BYTES, REPLY_PROJECT_GENESIS_MAGIC_V3,
    REPLY_PROJECT_MAGIC, REPLY_PROJECT_RESOURCE_GENESIS_BYTES_V4,
    REPLY_PROJECT_RESOURCE_GENESIS_MAGIC_V4, REPLY_RESERVATION_BYTES, REPLY_RESERVATION_MAGIC,
    REPLY_RESOURCE_GENESIS_MAGIC, REPLY_RETIREMENT_MAGIC, REQUEST_BYTES,
    REQUEST_CURRENT_NIX_MAGIC_V1, REQUEST_FIRST_SUCCESSOR_BYTES, REQUEST_FIRST_SUCCESSOR_MAGIC,
    REQUEST_GENESIS_BYTES, REQUEST_GENESIS_MAGIC, REQUEST_PROJECT_CONTINUATION_MAGIC,
    REQUEST_PROJECT_GENESIS_MAGIC_V3, REQUEST_PROJECT_RESOURCE_GENESIS_BYTES_V4,
    REQUEST_PROJECT_RESOURCE_GENESIS_MAGIC_V4, REQUEST_RESOURCE_CONTINUATION_MAGIC_V5,
    REQUEST_RESOURCE_GENESIS_MAGIC, REQUEST_RESOURCE_SUCCESSOR_BYTES,
    REQUEST_RESOURCE_SUCCESSOR_MAGIC_V4, SOURCE_FIRST_SUCCESSOR_READBACK_BYTES_V2,
    SOURCE_SIGNER_SOCKET_PATH_V1, SourceSignerRequestModeV1, SourceSuccessorRequestRecipe,
    decode_first_successor_request, decode_genesis_request, decode_project_genesis_request_v3,
    decode_request_mode, decode_source_successor_request, encode_resource_successor_request,
    invalid_data, require_socket_path_custody, write_framed_reply,
};

const CREDENTIAL_DIRECTORY: &str = "/run/credentials/aos-sandbox-source-signerd.service";

// This bounded transport carrier preserves the legacy owning array. Neither
// variant can construct a held current consumer or a paid resource grant.
enum SourceSuccessorReplyData {
    Legacy([u8; SOURCE_FIRST_SUCCESSOR_READBACK_BYTES_V2]),
    Resource(Vec<u8>),
}

impl SourceSuccessorReplyData {
    fn bytes(&self) -> &[u8] {
        match self { Self::Legacy(bytes) => bytes, Self::Resource(bytes) => bytes }
    }
}

/// Serves root requests using only the read-only Source view and private seed.
///
/// # Errors
///
/// Rejects wrong process identity, socket activation, credentials, or listener
/// custody. Rejected individual requests receive no packet.
pub fn run_source_signer_service_v1(
    controller_uid: u32,
    controller_gid: u32,
    signer_uid: u32,
    signer_gid: u32,
) -> Result<(), Box<dyn Error>> {
    if controller_uid == 0
        || controller_gid == 0
        || signer_uid == 0
        || signer_gid == 0
        || controller_uid == signer_uid
        || rustix::process::getuid().as_raw() != signer_uid
        || rustix::process::geteuid().as_raw() != signer_uid
        || rustix::process::getgid().as_raw() != signer_gid
        || rustix::process::getegid().as_raw() != signer_gid
    {
        return Err(invalid_data("wrong Source signer process identity").into());
    }
    if std::env::var_os("CREDENTIALS_DIRECTORY").as_deref()
        != Some(std::ffi::OsStr::new(CREDENTIAL_DIRECTORY))
        || std::env::var_os("LISTEN_FDS").is_some()
        || std::env::var_os("LISTEN_PID").is_some()
    {
        return Err(invalid_data("wrong Source signer activation custody").into());
    }
    let credentials = SourceSignerCredentialV1::load()?;
    let listener = UnixListener::from(rustix::io::dup(io::stdin().as_fd())?);
    if !socket_acceptconn(&listener)?
        || listener.local_addr()?.as_pathname() != Some(Path::new(SOURCE_SIGNER_SOCKET_PATH_V1))
    {
        return Err(invalid_data("wrong Source signer listening socket").into());
    }
    require_socket_path_custody(signer_uid, controller_gid)?;

    loop {
        let (mut stream, _) = listener.accept()?;
        if let Err(error) = serve_request(&mut stream, controller_uid, controller_gid, &credentials)
        {
            eprintln!("aos-sandbox-source-signerd: rejected request: {error}");
        }
    }
}

fn serve_request(
    stream: &mut UnixStream,
    controller_uid: u32,
    controller_gid: u32,
    credentials: &SourceSignerCredentialV1,
) -> Result<(), Box<dyn Error>> {
    let peer = socket_peercred(&*stream)?;
    if peer.uid.as_raw() != 0 || peer.gid.as_raw() != controller_gid {
        return Err(invalid_data("unexpected Source signer peer").into());
    }
    stream.set_read_timeout(Some(FLIGHT_TIMEOUT))?;
    stream.set_write_timeout(Some(FLIGHT_TIMEOUT))?;
    let mut request = [0; REQUEST_BYTES];
    let initial_read = stream.read_exact(&mut request);
    if request[..8] == *REQUEST_CURRENT_NIX_MAGIC_V1 {
        initial_read?;
        // The original paid receiving origin is not issued yet. Refuse before
        // any selected context growth, key access or Source observation.
        return Err(aos_sandbox::policy_compiler::CurrentNixPreflightDataErrorV1::Changed.into());
    }
    initial_read?;
    if request[..8] == *REQUEST_FIRST_SUCCESSOR_MAGIC
        || request[..8] == *REQUEST_PROJECT_CONTINUATION_MAGIC
        || request[..8] == *REQUEST_RESOURCE_SUCCESSOR_MAGIC_V4
        || request[..8] == *REQUEST_RESOURCE_CONTINUATION_MAGIC_V5
    {
        let recipe = if request[..8] == *REQUEST_FIRST_SUCCESSOR_MAGIC {
            SourceSuccessorRequestRecipe::SingleProjectV2
        } else if request[..8] == *REQUEST_PROJECT_CONTINUATION_MAGIC {
            SourceSuccessorRequestRecipe::MixedProjectsV3
        } else if request[..8] == *REQUEST_RESOURCE_SUCCESSOR_MAGIC_V4 {
            SourceSuccessorRequestRecipe::ResourceSingleProjectV4
        } else {
            SourceSuccessorRequestRecipe::ResourceMixedProjectsV5
        };
        let (nonce, context) = if recipe.resource() {
            let mut expanded = [0; REQUEST_RESOURCE_SUCCESSOR_BYTES];
            expanded[..REQUEST_BYTES].copy_from_slice(&request);
            stream.read_exact(&mut expanded[REQUEST_BYTES..])?;
            require_request_eof(stream)?;
            let nonce: [u8; 16] = expanded[8..24].try_into()
                .map_err(|_| invalid_data("invalid resource successor nonce"))?;
            let context = RootFirstSourceSuccessorIntentV2::decode(&expanded[72..]).map_err(io::Error::other)?;
            let mixed = matches!(recipe, SourceSuccessorRequestRecipe::ResourceMixedProjectsV5);
            if encode_resource_successor_request(nonce, &context, mixed)? != expanded {
                return Err(invalid_data("noncanonical resource successor request").into());
            }
            (nonce, context)
        } else {
            let mut expanded = [0; REQUEST_FIRST_SUCCESSOR_BYTES];
            expanded[..REQUEST_BYTES].copy_from_slice(&request);
            stream.read_exact(&mut expanded[REQUEST_BYTES..])?;
            require_request_eof(stream)?;
            match recipe {
                SourceSuccessorRequestRecipe::SingleProjectV2 => decode_first_successor_request(&expanded)?,
                SourceSuccessorRequestRecipe::MixedProjectsV3 => decode_source_successor_request(&expanded, recipe)?,
                _ => return Err(invalid_data("invalid legacy successor purpose").into()),
            }
        };
        if context.source_uid() != controller_uid { return Err(invalid_data("foreign successor Source UID").into()); }
        let signing_key_result = credentials.signing_key();
        let Ok(signing_key) = &signing_key_result else { std::process::exit(1); };
        let returned = match recipe {
            SourceSuccessorRequestRecipe::SingleProjectV2 => sign_fixed_source_first_successor_readback_v2(
                controller_uid, nonce, &context, credentials.generation(), signing_key,
            ).map(SourceSuccessorReplyData::Legacy),
            SourceSuccessorRequestRecipe::MixedProjectsV3 => sign_fixed_source_project_continuation_readback_v3(
                controller_uid, nonce, &context, credentials.generation(), signing_key,
            ).map(SourceSuccessorReplyData::Legacy),
            SourceSuccessorRequestRecipe::ResourceSingleProjectV4 | SourceSuccessorRequestRecipe::ResourceMixedProjectsV5 => {
                aos_sandbox::policy_compiler::sign_fixed_source_resource_successor_readback_v4(
                    controller_uid, nonce, &context, credentials.generation(), signing_key,
                    matches!(recipe, SourceSuccessorRequestRecipe::ResourceMixedProjectsV5),
                ).map(SourceSuccessorReplyData::Resource)
            }
        };
        // Each independent post is attempted after the real signature Result
        // is named. A later failure cannot replace its first returned cause.
        // The existing credential owner retains startup seed bytes; it does
        // not provide a fresh credential-file-name observation API.
        let credential_post = credentials.signing_key();
        let peer_post = socket_peercred(&*stream);
        let Ok(packet) = &returned else { std::process::exit(1); };
        let Ok(later_key) = &credential_post else { std::process::exit(1); };
        let Ok(later_peer) = &peer_post else { std::process::exit(1); };
        if later_key.verifying_key() != signing_key.verifying_key()
            || later_peer.uid != peer.uid || later_peer.gid != peer.gid || later_peer.pid != peer.pid
        { std::process::exit(1); }

        let sent = match packet {
            SourceSuccessorReplyData::Legacy(_) => write_framed_reply::<REPLY_FIRST_SUCCESSOR_BYTES>(stream, recipe.reply_magic(), packet.bytes()),
            SourceSuccessorReplyData::Resource(bytes) => match bytes.len() {
                2960 => write_framed_reply::<2968>(stream, recipe.reply_magic(), bytes),
                3136 => write_framed_reply::<3144>(stream, recipe.reply_magic(), bytes),
                _ => Err(invalid_data("unknown resource successor reply width")),
            }
        };
        let credential_after_send = credentials.signing_key();
        let peer_after_send = socket_peercred(&*stream);
        if sent.is_err() || credential_after_send.is_err() || peer_after_send.is_err() {
            // These whole original Results and the startup credential owner
            // survive termination. The lower reader/view pre-return boundary
            // is unchanged and is not claimed repaired by this wrapper.
            std::process::exit(1);
        }
        if let (Ok(key), Ok(later)) = (&credential_after_send, &peer_after_send) {
            if key.verifying_key() != signing_key.verifying_key()
                || later.uid != peer.uid || later.gid != peer.gid || later.pid != peer.pid
            { std::process::exit(1); }
        }
        let shutdown = stream.shutdown(std::net::Shutdown::Write);
        let credential_after_shutdown = credentials.signing_key();
        let peer_after_shutdown = socket_peercred(&*stream);
        if shutdown.is_err() || credential_after_shutdown.is_err() || peer_after_shutdown.is_err() {
            std::process::exit(1);
        }
        if let (Ok(key), Ok(later)) = (&credential_after_shutdown, &peer_after_shutdown) {
            if key.verifying_key() != signing_key.verifying_key()
                || later.uid != peer.uid || later.gid != peer.gid || later.pid != peer.pid
            { std::process::exit(1); }
        }
        return Ok(());
    }
    if request[..8] == *REQUEST_PROJECT_GENESIS_MAGIC_V3
        || request[..8] == *REQUEST_PROJECT_RESOURCE_GENESIS_MAGIC_V4
        || request[..8] == *REQUEST_RESOURCE_GENESIS_MAGIC {
        let strict_resource = request[..8] == *REQUEST_RESOURCE_GENESIS_MAGIC;
        let resource_version = strict_resource || request[..8] == *REQUEST_PROJECT_RESOURCE_GENESIS_MAGIC_V4;
        let request_bytes = if resource_version { REQUEST_PROJECT_RESOURCE_GENESIS_BYTES_V4 } else { REQUEST_GENESIS_BYTES };
        let mut expanded = [0; REQUEST_PROJECT_RESOURCE_GENESIS_BYTES_V4];
        expanded[..REQUEST_BYTES].copy_from_slice(&request);
        stream.read_exact(&mut expanded[REQUEST_BYTES..request_bytes])?;
        require_request_eof(stream)?;
        let strict_inputs = strict_resource
            .then(|| decode_genesis_request(&expanded[..request_bytes])).transpose()?;
        let project_inputs = (!strict_resource)
            .then(|| decode_project_genesis_request_v3(&expanded[..request_bytes])).transpose()?;
        let signing_key_result = credentials.signing_key();
        let Ok(signing_key) = &signing_key_result else { std::process::exit(1); };
        let returned = if let Some((challenge, project, context)) = &strict_inputs {
            sign_fixed_source_tree_genesis_readback_v3(
                controller_uid, *project, *challenge, context.as_ref(), credentials.generation(), signing_key,
            )
        } else {
            let (challenge, context) = project_inputs.as_ref()
                .ok_or_else(|| invalid_data("missing selected genesis recipe"))?;
            sign_fixed_source_project_genesis_readback_v4(
                controller_uid, *challenge, context, credentials.generation(), signing_key,
            )
        };
        let credential_post = credentials.signing_key();
        let peer_post = socket_peercred(&*stream);
        let Ok(packet) = &returned else { std::process::exit(1); };
        let Ok(later_key) = &credential_post else { std::process::exit(1); };
        let Ok(later_peer) = &peer_post else { std::process::exit(1); };
        if later_key.verifying_key() != signing_key.verifying_key()
            || later_peer.uid != peer.uid || later_peer.gid != peer.gid || later_peer.pid != peer.pid
        { std::process::exit(1); }
        let sent = if resource_version {
            write_framed_reply::<REPLY_PROJECT_RESOURCE_GENESIS_BYTES_V4>(stream,
                if strict_resource { REPLY_RESOURCE_GENESIS_MAGIC } else { REPLY_PROJECT_RESOURCE_GENESIS_MAGIC_V4 },
                packet.as_ref())
        } else {
            write_framed_reply::<REPLY_GENESIS_BYTES>(stream, REPLY_PROJECT_GENESIS_MAGIC_V3, packet.as_ref())
        };
        let credential_after_send = credentials.signing_key();
        let peer_after_send = socket_peercred(&*stream);
        if sent.is_err() || credential_after_send.is_err() || peer_after_send.is_err() { std::process::exit(1); }
        if let (Ok(key), Ok(later)) = (&credential_after_send, &peer_after_send) {
            if key.verifying_key() != signing_key.verifying_key()
                || later.uid != peer.uid || later.gid != peer.gid || later.pid != peer.pid
            { std::process::exit(1); }
        }
        let shutdown = stream.shutdown(std::net::Shutdown::Write);
        let credential_after_shutdown = credentials.signing_key();
        let peer_after_shutdown = socket_peercred(&*stream);
        if shutdown.is_err() || credential_after_shutdown.is_err() || peer_after_shutdown.is_err() { std::process::exit(1); }
        if let (Ok(key), Ok(later)) = (&credential_after_shutdown, &peer_after_shutdown) {
            if key.verifying_key() != signing_key.verifying_key()
                || later.uid != peer.uid || later.gid != peer.gid || later.pid != peer.pid
            { std::process::exit(1); }
        }
        return Ok(());
    }
    if request[..8] == *REQUEST_GENESIS_MAGIC {
        let mut expanded = [0; REQUEST_GENESIS_BYTES];
        expanded[..REQUEST_BYTES].copy_from_slice(&request);
        stream.read_exact(&mut expanded[REQUEST_BYTES..])?;
        require_request_eof(stream)?;
        let (challenge, project, context) = decode_genesis_request(&expanded)?;
        let signing_key = credentials.signing_key()?;
        let packet = sign_fixed_source_tree_genesis_readback_v2(
            controller_uid,
            project,
            challenge,
            context.as_ref(),
            credentials.generation(),
            &signing_key,
        )?;
        write_framed_reply::<REPLY_GENESIS_BYTES>(stream, REPLY_GENESIS_MAGIC, &packet)?;
        stream.shutdown(std::net::Shutdown::Write)?;
        return Ok(());
    }
    require_request_eof(stream)?;
    let (challenge, project, mode) = decode_request_mode(&request)?;
    let signing_key = credentials.signing_key()?;
    if mode == SourceSignerRequestModeV1::ProjectCompletedTerminal {
        let packet = sign_fixed_source_project_completed_terminal_readback_v1(
            controller_uid,
            challenge,
            credentials.generation(),
            &signing_key,
        )?;
        write_framed_reply::<REPLY_COMPLETED_BYTES>(stream, REPLY_COMPLETED_MAGIC, &packet)?;
    } else if mode == SourceSignerRequestModeV1::ProjectAdmission {
        let packet = sign_fixed_source_project_admission_readback_v1(
            controller_uid,
            project,
            challenge,
            credentials.generation(),
            &signing_key,
        )?;
        write_framed_reply::<REPLY_PROJECT_BYTES>(stream, REPLY_PROJECT_MAGIC, &packet)?;
    } else if mode == SourceSignerRequestModeV1::ProjectReservation {
        let packet = sign_fixed_source_project_reservation_readback_v1(
            controller_uid,
            challenge.nonce(),
            project,
            challenge.cut(),
            credentials.generation(),
            &signing_key,
        )?;
        write_framed_reply::<REPLY_RESERVATION_BYTES>(stream, REPLY_RESERVATION_MAGIC, &packet)?;
    } else if mode == SourceSignerRequestModeV1::ProjectRetirement {
        let packet = sign_fixed_source_project_retirement_readback_v1(
            controller_uid,
            project,
            challenge,
            credentials.generation(),
            &signing_key,
        )?;
        write_framed_reply::<REPLY_PROJECT_BYTES>(stream, REPLY_RETIREMENT_MAGIC, &packet)?;
    } else if mode == SourceSignerRequestModeV1::HeldNames {
        let packet = sign_fixed_source_signer_readback_v2(
            controller_uid,
            project,
            challenge,
            credentials.generation(),
            &signing_key,
        )?;
        write_framed_reply::<REPLY_NAMES_BYTES>(stream, REPLY_NAMES_MAGIC, &packet)?;
    } else {
        let packet = sign_fixed_source_signer_readback_v1(
            controller_uid,
            project,
            challenge,
            credentials.generation(),
            &signing_key,
        )?;
        write_framed_reply::<REPLY_BYTES>(stream, REPLY_MAGIC, &packet)?;
    }
    stream.shutdown(std::net::Shutdown::Write)?;
    Ok(())
}

fn require_request_eof(stream: &mut UnixStream) -> io::Result<()> {
    let mut trailing = [0];
    if stream.read(&mut trailing)? != 0 {
        return Err(invalid_data("trailing Source signer request bytes"));
    }
    Ok(())
}
