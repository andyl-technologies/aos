//! Bounded root ingress to the separate Source-only readback signer.
//!
//! The signer accepts only the root policy peer (UID 0, Controller GID) and
//! opens its private read-only Source journal view for each request. Root
//! supplies an independently spent challenge and verifies the reply against
//! its protected public pin and expected hold.
//! This transport neither adopts Controller's writer nor authorizes Q04/Create.
//!
//! The private service owner contains fixed activation and complete daemon
//! request dispatch. The private Root client owner retains complete request,
//! transport and verification recipes. Shared wire codecs remain here, and
//! the public entries directly expose the existing recipes.
//!
//! ```text
//! AOSSSR01 | nonce[16] | root-cut[32] | project[16]
//! AOSSSP01 | AOSSRB01 packet[288]
//! AOSSSR08 | fresh-nonce[16] | intent[32] | project[16] | AOSSGX01[664]
//! AOSSSP08 | unchanged AOSSGO01 observation[928]
//! AOSSSR09 | fresh-nonce16 | original-intent32 | project16 | Intent1248
//! AOSSSP09 | first-successor observation2784
//! AOSSSR10 | fresh-nonce16 | original-intent32 | project16 | Intent1248
//! AOSSSP10 | explicit mixed-project Source observation2784
//! AOSSSR12 | selected full-resource Project context840; AOSSSP12 | packet1104
//! AOSSSR13 | strict full-resource genesis context840; AOSSSP13 | packet1104
//! AOSSSR14 | strict full-resource Intent1424; AOSSSP14 | observation2960/3136
//! AOSSSR15 | mixed full-resource Intent1424; AOSSSP15 | observation2960/3136
//! AOSSSR16 | context280 | intent-slot1424; AOSSSP16 | context + native + signature
//! ```

use std::fs;
use std::io::{self, Read as _, Write as _};
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use aos_sandbox::policy_compiler::{
    RootFirstSourceSuccessorIntentV2,
    SOURCE_FIRST_SUCCESSOR_READBACK_BYTES_V2,
    SOURCE_HOLD_READBACK_BYTES_V1,
    SOURCE_HOLD_READBACK_BYTES_V2,
    SOURCE_PROJECT_ADMISSION_READBACK_BYTES_V1,
    SOURCE_PROJECT_COMPLETED_TERMINAL_READBACK_BYTES_V1,
    SOURCE_PROJECT_RESERVATION_READBACK_BYTES_V1,
    SOURCE_PROJECT_RESOURCE_GENESIS_READBACK_BYTES_V4,
    SOURCE_TREE_GENESIS_INTENT_CONTEXT_BYTES_V1,
    SOURCE_TREE_GENESIS_INTENT_CONTEXT_BYTES_V2,
    SOURCE_TREE_GENESIS_READBACK_BYTES_V1,
    SourceHoldReadbackChallengeV1,
    SourceProjectGenesisChallengeV3,
    SourceTreeGenesisChallengeV1,
    SourceTreeGenesisIntentContextV1,
};
use aos_sandbox_core::{ObjectDigest, ProjectId};

mod current_nix;
mod root_client;
mod service;

pub use current_nix::CurrentNixSourceExchangeAttemptV1;
pub use root_client::{
    request_root_source_first_successor_readback_v2,
    request_root_source_project_admission_readback_v1,
    request_root_source_project_completed_terminal_readback_v1,
    request_root_source_project_continuation_readback_v3,
    request_root_source_project_genesis_readback_v3,
    request_root_source_project_genesis_readback_v4,
    request_root_source_project_reservation_readback_v1,
    request_root_source_project_retirement_readback_v1,
    request_root_source_resource_successor_readback_v4,
    request_root_source_signer_readback_v1,
    request_root_source_signer_readback_with_names_v2,
    request_root_source_tree_genesis_readback_v2,
    request_root_source_tree_genesis_readback_v3,
    request_root_staged_q04_source_readback_v2,
};
pub use service::run_source_signer_service_v1;

/// Names the sole systemd-owned Source signer ingress socket.
pub const SOURCE_SIGNER_SOCKET_PATH_V1: &str = "/run/aos/sandbox-source-signerd.sock";

const REQUEST_MAGIC: &[u8; 8] = b"AOSSSR01";
const REPLY_MAGIC: &[u8; 8] = b"AOSSSP01";
const REQUEST_NAMES_MAGIC: &[u8; 8] = b"AOSSSR02";
const REPLY_NAMES_MAGIC: &[u8; 8] = b"AOSSSP02";
const REQUEST_PROJECT_MAGIC: &[u8; 8] = b"AOSSSR03";
const REPLY_PROJECT_MAGIC: &[u8; 8] = b"AOSSSP03";
const REQUEST_RETIREMENT_MAGIC: &[u8; 8] = b"AOSSSR04";
const REPLY_RETIREMENT_MAGIC: &[u8; 8] = b"AOSSSP04";
const REQUEST_RESERVATION_MAGIC: &[u8; 8] = b"AOSSSR05";
const REPLY_RESERVATION_MAGIC: &[u8; 8] = b"AOSSSP05";
const REQUEST_COMPLETED_MAGIC: &[u8; 8] = b"AOSSSR06";
const REPLY_COMPLETED_MAGIC: &[u8; 8] = b"AOSSSP06";
const REQUEST_GENESIS_MAGIC: &[u8; 8] = b"AOSSSR08";
const REPLY_GENESIS_MAGIC: &[u8; 8] = b"AOSSSP08";
const REQUEST_FIRST_SUCCESSOR_MAGIC: &[u8; 8] = b"AOSSSR09";
const REPLY_FIRST_SUCCESSOR_MAGIC: &[u8; 8] = b"AOSSSP09";
const REQUEST_PROJECT_CONTINUATION_MAGIC: &[u8; 8] = b"AOSSSR10";
const REPLY_PROJECT_CONTINUATION_MAGIC: &[u8; 8] = b"AOSSSP10";
const REQUEST_PROJECT_GENESIS_MAGIC_V3: &[u8; 8] = b"AOSSSR11";
const REPLY_PROJECT_GENESIS_MAGIC_V3: &[u8; 8] = b"AOSSSP11";
const REQUEST_PROJECT_RESOURCE_GENESIS_MAGIC_V4: &[u8; 8] = b"AOSSSR12";
const REPLY_PROJECT_RESOURCE_GENESIS_MAGIC_V4: &[u8; 8] = b"AOSSSP12";
const REQUEST_PROJECT_RESOURCE_GENESIS_BYTES_V4: usize = REQUEST_BYTES + SOURCE_TREE_GENESIS_INTENT_CONTEXT_BYTES_V2;
const REPLY_PROJECT_RESOURCE_GENESIS_BYTES_V4: usize = 8 + SOURCE_PROJECT_RESOURCE_GENESIS_READBACK_BYTES_V4;
const REQUEST_RESOURCE_GENESIS_MAGIC: &[u8; 8] = b"AOSSSR13";
const REPLY_RESOURCE_GENESIS_MAGIC: &[u8; 8] = b"AOSSSP13";
const REQUEST_FIRST_SUCCESSOR_BYTES: usize = REQUEST_BYTES + 1248;
const REPLY_FIRST_SUCCESSOR_BYTES: usize = 8 + SOURCE_FIRST_SUCCESSOR_READBACK_BYTES_V2;
const REQUEST_RESOURCE_SUCCESSOR_MAGIC_V4: &[u8; 8] = b"AOSSSR14";
const REPLY_RESOURCE_SUCCESSOR_MAGIC_V4: &[u8; 8] = b"AOSSSP14";
const REQUEST_RESOURCE_CONTINUATION_MAGIC_V5: &[u8; 8] = b"AOSSSR15";
const REPLY_RESOURCE_CONTINUATION_MAGIC_V5: &[u8; 8] = b"AOSSSP15";
const REQUEST_CURRENT_NIX_MAGIC_V1: &[u8; 8] = b"AOSSSR16";
const REQUEST_RESOURCE_SUCCESSOR_BYTES: usize = 72 + 1424;
const REPLY_GENESIS_BYTES: usize = 8 + SOURCE_TREE_GENESIS_READBACK_BYTES_V1;
const REPLY_COMPLETED_BYTES: usize = 8 + SOURCE_PROJECT_COMPLETED_TERMINAL_READBACK_BYTES_V1;
const REQUEST_BYTES: usize = 72;
const REQUEST_GENESIS_BYTES: usize = REQUEST_BYTES + SOURCE_TREE_GENESIS_INTENT_CONTEXT_BYTES_V1;
const REPLY_BYTES: usize = 8 + SOURCE_HOLD_READBACK_BYTES_V1;
const REPLY_NAMES_BYTES: usize = 8 + SOURCE_HOLD_READBACK_BYTES_V2;
const REPLY_PROJECT_BYTES: usize = 8 + SOURCE_PROJECT_ADMISSION_READBACK_BYTES_V1;
const REPLY_RESERVATION_BYTES: usize = 8 + SOURCE_PROJECT_RESERVATION_READBACK_BYTES_V1;
const FLIGHT_TIMEOUT: Duration = Duration::from_secs(5);
fn encode_project_genesis_request_v3(
    challenge: SourceProjectGenesisChallengeV3,
    context: &SourceTreeGenesisIntentContextV1,
) -> io::Result<[u8; REQUEST_GENESIS_BYTES]> {
    encode_project_genesis_request(challenge, context)
}

fn encode_project_genesis_request<const BYTES: usize>(
    challenge: SourceProjectGenesisChallengeV3,
    context: &SourceTreeGenesisIntentContextV1,
) -> io::Result<[u8; BYTES]> {
    if context.project() != challenge.project() { return Err(invalid_data("foreign selected genesis context")); }
    let resource_version = context.has_resource_authorization();
    let context_bytes = context.encode();
    if BYTES != REQUEST_BYTES + context_bytes.len() {
        return Err(invalid_data("foreign selected genesis context width"));
    }
    let mut request = [0; BYTES];
    request[..8].copy_from_slice(if resource_version { REQUEST_PROJECT_RESOURCE_GENESIS_MAGIC_V4 } else { REQUEST_PROJECT_GENESIS_MAGIC_V3 });
    request[8..24].copy_from_slice(&challenge.nonce());
    request[24..56].copy_from_slice(challenge.intent().map_or([0; 32], |digest| *digest.as_bytes()).as_slice());
    request[56..72].copy_from_slice(challenge.project().as_bytes());
    request[REQUEST_BYTES..].copy_from_slice(&context_bytes);
    Ok(request)
}

fn decode_project_genesis_request_v3(
    request: &[u8],
) -> io::Result<(SourceProjectGenesisChallengeV3, SourceTreeGenesisIntentContextV1)> {
    let resource_version = request.len() == REQUEST_PROJECT_RESOURCE_GENESIS_BYTES_V4
        && request.get(..8) == Some(REQUEST_PROJECT_RESOURCE_GENESIS_MAGIC_V4.as_slice());
    let legacy = request.len() == REQUEST_GENESIS_BYTES
        && request.get(..8) == Some(REQUEST_PROJECT_GENESIS_MAGIC_V3.as_slice());
    if !resource_version && !legacy { return Err(invalid_data("foreign selected genesis request")); }
    let nonce = request[8..24].try_into().map_err(|_| invalid_data("invalid selected nonce"))?;
    let intent: [u8; 32] = request[24..56].try_into().map_err(|_| invalid_data("invalid original intent"))?;
    let project = ProjectId::from_bytes(request[56..72].try_into().map_err(|_| invalid_data("invalid selected project"))?);
    let challenge = SourceProjectGenesisChallengeV3::new(nonce, project,
        (intent != [0; 32]).then_some(ObjectDigest::from_bytes(intent))).map_err(io::Error::other)?;
    let context = SourceTreeGenesisIntentContextV1::decode(&request[REQUEST_BYTES..]).map_err(io::Error::other)?;
    if context.has_resource_authorization() != resource_version {
        return Err(invalid_data("noncanonical selected genesis context recipe"));
    }
    let canonical = if resource_version {
        encode_project_genesis_request::<REQUEST_PROJECT_RESOURCE_GENESIS_BYTES_V4>(challenge, &context)?.as_slice() == request
    } else {
        encode_project_genesis_request_v3(challenge, &context)?.as_slice() == request
    };
    if !canonical { return Err(invalid_data("noncanonical selected genesis request")); }
    Ok((challenge, context))
}

#[derive(Clone, Copy)]
enum SourceSuccessorRequestRecipe {
    SingleProjectV2,
    MixedProjectsV3,
    ResourceSingleProjectV4,
    ResourceMixedProjectsV5,
}

impl SourceSuccessorRequestRecipe {
    const fn request_magic(self) -> &'static [u8; 8] {
        match self {
            Self::SingleProjectV2 => REQUEST_FIRST_SUCCESSOR_MAGIC,
            Self::MixedProjectsV3 => REQUEST_PROJECT_CONTINUATION_MAGIC,
            Self::ResourceSingleProjectV4 => REQUEST_RESOURCE_SUCCESSOR_MAGIC_V4,
            Self::ResourceMixedProjectsV5 => REQUEST_RESOURCE_CONTINUATION_MAGIC_V5,
        }
    }

    const fn reply_magic(self) -> &'static [u8; 8] {
        match self {
            Self::SingleProjectV2 => REPLY_FIRST_SUCCESSOR_MAGIC,
            Self::MixedProjectsV3 => REPLY_PROJECT_CONTINUATION_MAGIC,
            Self::ResourceSingleProjectV4 => REPLY_RESOURCE_SUCCESSOR_MAGIC_V4,
            Self::ResourceMixedProjectsV5 => REPLY_RESOURCE_CONTINUATION_MAGIC_V5,
        }
    }

    const fn resource(self) -> bool {
        matches!(self, Self::ResourceSingleProjectV4 | Self::ResourceMixedProjectsV5)
    }
}

fn encode_resource_successor_request(
    fresh_nonce: [u8; 16], context: &RootFirstSourceSuccessorIntentV2, mixed: bool,
) -> io::Result<[u8; REQUEST_RESOURCE_SUCCESSOR_BYTES]> {
    if context.as_bytes().len() != 1424 || fresh_nonce == [0; 16] {
        return Err(invalid_data("invalid resource successor context width"));
    }
    let mut request = [0; REQUEST_RESOURCE_SUCCESSOR_BYTES];
    request[..8].copy_from_slice(if mixed { REQUEST_RESOURCE_CONTINUATION_MAGIC_V5 } else { REQUEST_RESOURCE_SUCCESSOR_MAGIC_V4 });
    request[8..24].copy_from_slice(&fresh_nonce);
    request[24..56].copy_from_slice(context.digest().as_bytes());
    request[56..72].copy_from_slice(context.project().as_bytes());
    request[72..].copy_from_slice(context.as_bytes());
    Ok(request)
}

fn encode_first_successor_request(fresh_nonce: [u8; 16], context: &RootFirstSourceSuccessorIntentV2) -> [u8; REQUEST_FIRST_SUCCESSOR_BYTES] {
    encode_source_successor_request(fresh_nonce, context, SourceSuccessorRequestRecipe::SingleProjectV2)
}

fn encode_source_successor_request(
    fresh_nonce: [u8; 16], context: &RootFirstSourceSuccessorIntentV2,
    recipe: SourceSuccessorRequestRecipe,
) -> [u8; REQUEST_FIRST_SUCCESSOR_BYTES] {
    let mut request = [0; REQUEST_FIRST_SUCCESSOR_BYTES];
    request[..8].copy_from_slice(recipe.request_magic());
    request[8..24].copy_from_slice(&fresh_nonce);
    request[24..56].copy_from_slice(context.digest().as_bytes());
    request[56..72].copy_from_slice(context.project().as_bytes());
    request[72..].copy_from_slice(context.as_bytes());
    request
}

fn decode_first_successor_request(request: &[u8; REQUEST_FIRST_SUCCESSOR_BYTES])
    -> io::Result<([u8; 16], RootFirstSourceSuccessorIntentV2)>
{
    decode_source_successor_request(request, SourceSuccessorRequestRecipe::SingleProjectV2)
}

fn decode_source_successor_request(
    request: &[u8; REQUEST_FIRST_SUCCESSOR_BYTES], recipe: SourceSuccessorRequestRecipe,
) -> io::Result<([u8; 16], RootFirstSourceSuccessorIntentV2)> {
    let nonce: [u8; 16] = request[8..24].try_into().map_err(|_| invalid_data("invalid successor nonce"))?;
    let context = RootFirstSourceSuccessorIntentV2::decode(&request[72..]).map_err(io::Error::other)?;
    if nonce == [0; 16] || encode_source_successor_request(nonce, &context, recipe) != *request {
        return Err(invalid_data("noncanonical first-successor signer request"));
    }
    Ok((nonce, context))
}

fn encode_genesis_request(
    challenge: SourceTreeGenesisChallengeV1,
    project: Option<ProjectId>,
    intent_context: Option<&SourceTreeGenesisIntentContextV1>,
) -> io::Result<[u8; REQUEST_GENESIS_BYTES]> {
    encode_strict_genesis_request(challenge, project, intent_context)
}

fn encode_strict_genesis_request<const BYTES: usize>(
    challenge: SourceTreeGenesisChallengeV1,
    project: Option<ProjectId>,
    intent_context: Option<&SourceTreeGenesisIntentContextV1>,
) -> io::Result<[u8; BYTES]> {
    if project.is_some() != challenge.intent().is_some()
        || project.is_some_and(|project| project.as_bytes() == &[0; 16])
        || project.is_some() != intent_context.is_some()
        || intent_context.is_some_and(|context| Some(context.project()) != project)
    {
        return Err(invalid_data("mixed Source genesis scope"));
    }
    let resource = intent_context.is_some_and(SourceTreeGenesisIntentContextV1::has_resource_authorization);
    let expected = if resource { REQUEST_PROJECT_RESOURCE_GENESIS_BYTES_V4 } else { REQUEST_GENESIS_BYTES };
    if BYTES != expected {
        return Err(invalid_data("foreign Source genesis context width"));
    }
    let context_bytes = intent_context.map(SourceTreeGenesisIntentContextV1::encode);
    if context_bytes.as_ref().is_some_and(|bytes| bytes.len() != BYTES - REQUEST_BYTES) {
        return Err(invalid_data("foreign Source genesis context width"));
    }
    let mut request = [0; BYTES];
    request[..8].copy_from_slice(if resource { REQUEST_RESOURCE_GENESIS_MAGIC } else { REQUEST_GENESIS_MAGIC });
    request[8..24].copy_from_slice(&challenge.nonce());
    if let Some(intent) = challenge.intent() {
        request[24..56].copy_from_slice(intent.as_bytes());
    }
    if let Some(project) = project {
        request[56..72].copy_from_slice(project.as_bytes());
    }
    if let Some(bytes) = context_bytes {
        request[REQUEST_BYTES..].copy_from_slice(&bytes);
    }
    Ok(request)
}

fn decode_genesis_request(
    request: &[u8],
) -> io::Result<(
    SourceTreeGenesisChallengeV1,
    Option<ProjectId>,
    Option<SourceTreeGenesisIntentContextV1>,
)> {
    let resource = request.len() == REQUEST_PROJECT_RESOURCE_GENESIS_BYTES_V4
        && request.get(..8) == Some(REQUEST_RESOURCE_GENESIS_MAGIC.as_slice());
    let legacy = request.len() == REQUEST_GENESIS_BYTES
        && request.get(..8) == Some(REQUEST_GENESIS_MAGIC.as_slice());
    if !resource && !legacy {
        return Err(invalid_data("foreign Source genesis request"));
    }
    let nonce = request[8..24]
        .try_into()
        .map_err(|_| invalid_data("invalid genesis nonce"))?;
    let intent_bytes: [u8; 32] = request[24..56]
        .try_into()
        .map_err(|_| invalid_data("invalid genesis intent"))?;
    let project_bytes: [u8; 16] = request[56..72]
        .try_into()
        .map_err(|_| invalid_data("invalid genesis project"))?;
    let intent = (intent_bytes != [0; 32]).then_some(ObjectDigest::from_bytes(intent_bytes));
    let project = (project_bytes != [0; 16]).then_some(ProjectId::from_bytes(project_bytes));
    let challenge = SourceTreeGenesisChallengeV1::new(nonce, intent).map_err(io::Error::other)?;
    let context = project
        .map(|_| SourceTreeGenesisIntentContextV1::decode(&request[REQUEST_BYTES..]))
        .transpose()
        .map_err(io::Error::other)?;
    if context.as_ref().is_some_and(SourceTreeGenesisIntentContextV1::has_resource_authorization) != resource {
        return Err(invalid_data("foreign Source genesis context recipe"));
    }
    let canonical = if resource {
        encode_strict_genesis_request::<REQUEST_PROJECT_RESOURCE_GENESIS_BYTES_V4>(challenge, project, context.as_ref())?.as_slice() == request
    } else {
        encode_genesis_request(challenge, project, context.as_ref())?.as_slice() == request
    };
    if !canonical {
        return Err(invalid_data("noncanonical Source genesis request"));
    }
    Ok((challenge, project, context))
}

fn encode_request(
    challenge: SourceHoldReadbackChallengeV1,
    project: ProjectId,
) -> [u8; REQUEST_BYTES] {
    let mut bytes = [0; REQUEST_BYTES];
    bytes[..8].copy_from_slice(REQUEST_MAGIC);
    bytes[8..24].copy_from_slice(&challenge.nonce());
    bytes[24..56].copy_from_slice(challenge.cut().as_bytes());
    bytes[56..72].copy_from_slice(project.as_bytes());
    bytes
}

fn decode_request(
    bytes: &[u8; REQUEST_BYTES],
) -> io::Result<(SourceHoldReadbackChallengeV1, ProjectId)> {
    if &bytes[..8] != REQUEST_MAGIC {
        return Err(invalid_data("foreign Source signer request"));
    }
    let nonce = bytes[8..24]
        .try_into()
        .map_err(|_| invalid_data("invalid Source nonce"))?;
    let cut = ObjectDigest::from_bytes(
        bytes[24..56]
            .try_into()
            .map_err(|_| invalid_data("invalid Source root cut"))?,
    );
    let project = ProjectId::from_bytes(
        bytes[56..72]
            .try_into()
            .map_err(|_| invalid_data("invalid Source project"))?,
    );
    if project.as_bytes() == &[0; 16] {
        return Err(invalid_data("zero Source project"));
    }
    let challenge = SourceHoldReadbackChallengeV1::new(nonce, cut)
        .map_err(|_| invalid_data("noncanonical Source challenge"))?;
    Ok((challenge, project))
}

fn read_reply(stream: &mut UnixStream) -> io::Result<[u8; SOURCE_HOLD_READBACK_BYTES_V1]> {
    read_framed_reply::<REPLY_BYTES, SOURCE_HOLD_READBACK_BYTES_V1>(stream, REPLY_MAGIC)
}

fn read_names_reply(stream: &mut UnixStream) -> io::Result<[u8; SOURCE_HOLD_READBACK_BYTES_V2]> {
    read_framed_reply::<REPLY_NAMES_BYTES, SOURCE_HOLD_READBACK_BYTES_V2>(stream, REPLY_NAMES_MAGIC)
}

fn read_project_reply(
    stream: &mut UnixStream,
) -> io::Result<[u8; SOURCE_PROJECT_ADMISSION_READBACK_BYTES_V1]> {
    read_framed_reply::<REPLY_PROJECT_BYTES, SOURCE_PROJECT_ADMISSION_READBACK_BYTES_V1>(
        stream,
        REPLY_PROJECT_MAGIC,
    )
}

fn read_project_retirement_reply(
    stream: &mut UnixStream,
) -> io::Result<[u8; SOURCE_PROJECT_ADMISSION_READBACK_BYTES_V1]> {
    read_framed_reply::<REPLY_PROJECT_BYTES, SOURCE_PROJECT_ADMISSION_READBACK_BYTES_V1>(
        stream,
        REPLY_RETIREMENT_MAGIC,
    )
}

fn read_framed_reply<const REPLY: usize, const PACKET: usize>(
    stream: &mut UnixStream,
    magic: &[u8; 8],
) -> io::Result<[u8; PACKET]> {
    let mut reply = [0; REPLY];
    stream.read_exact(&mut reply)?;
    let mut trailing = [0];
    if reply.get(..8) != Some(magic.as_slice()) || stream.read(&mut trailing)? != 0 {
        return Err(invalid_data("invalid Source signer reply"));
    }
    reply
        .get(8..)
        .ok_or_else(|| invalid_data("invalid Source signer packet length"))?
        .try_into()
        .map_err(|_| invalid_data("invalid Source signer packet length"))
}

fn require_socket_path_custody(signer_uid: u32, socket_gid: u32) -> io::Result<()> {
    for parent in ["/run", "/run/aos"] {
        let metadata = fs::symlink_metadata(parent)?;
        if !metadata.file_type().is_dir()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.mode() & 0o022 != 0
        {
            return Err(invalid_data("unsafe Source signer socket parent"));
        }
    }
    let socket = fs::symlink_metadata(SOURCE_SIGNER_SOCKET_PATH_V1)?;
    if !socket.file_type().is_socket()
        || socket.uid() != signer_uid
        || socket.gid() != socket_gid
        || socket.mode() & 0o777 != 0o660
        || socket.nlink() != 1
    {
        return Err(invalid_data("unsafe Source signer socket node"));
    }
    Ok(())
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn write_framed_reply<const REPLY: usize>(
    stream: &mut UnixStream,
    magic: &[u8; 8],
    packet: &[u8],
) -> io::Result<()> {
    let mut reply = [0; REPLY];
    let payload = reply
        .get_mut(8..)
        .filter(|payload| payload.len() == packet.len())
        .ok_or_else(|| invalid_data("invalid Source signer reply length"))?;
    payload.copy_from_slice(packet);
    reply[..8].copy_from_slice(magic);
    stream.write_all(&reply)
}

fn decode_request_mode(
    request: &[u8; REQUEST_BYTES],
) -> io::Result<(
    SourceHoldReadbackChallengeV1,
    ProjectId,
    SourceSignerRequestModeV1,
)> {
    let mode = match request.get(..8) {
        Some(magic) if magic == REQUEST_MAGIC => SourceSignerRequestModeV1::Held,
        Some(magic) if magic == REQUEST_NAMES_MAGIC => SourceSignerRequestModeV1::HeldNames,
        Some(magic) if magic == REQUEST_PROJECT_MAGIC => {
            SourceSignerRequestModeV1::ProjectAdmission
        }
        Some(magic) if magic == REQUEST_RETIREMENT_MAGIC => {
            SourceSignerRequestModeV1::ProjectRetirement
        }
        Some(magic) if magic == REQUEST_RESERVATION_MAGIC => {
            SourceSignerRequestModeV1::ProjectReservation
        }
        Some(magic) if magic == REQUEST_COMPLETED_MAGIC => {
            SourceSignerRequestModeV1::ProjectCompletedTerminal
        }
        _ => return Err(invalid_data("foreign Source signer request")),
    };
    let mut canonical = *request;
    canonical[..8].copy_from_slice(REQUEST_MAGIC);
    let (challenge, project) = decode_request(&canonical)?;
    Ok((challenge, project, mode))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SourceSignerRequestModeV1 {
    Held,
    HeldNames,
    ProjectAdmission,
    ProjectRetirement,
    ProjectReservation,
    ProjectCompletedTerminal,
}



#[cfg(test)]
mod tests {
    use super::*;

    // Independent canonical DATA bytes for framing, not issuer or owner trust.
    fn genesis_context(project: ProjectId) -> SourceTreeGenesisIntentContextV1 {
        let mut context = [0; SOURCE_TREE_GENESIS_INTENT_CONTEXT_BYTES_V1];
        context[..8].copy_from_slice(b"AOSSGX01");
        context[8..10].copy_from_slice(&1_u16.to_be_bytes());
        context[16..20].copy_from_slice(&1000_u32.to_be_bytes());
        context[24..56].fill(9);
        let acceptance = &mut context[56..];
        acceptance[..8].copy_from_slice(b"AOSSGC01");
        acceptance[8..10].copy_from_slice(&1_u16.to_be_bytes());
        acceptance[16..32].copy_from_slice(project.as_bytes());
        acceptance[480..512].fill(4);
        acceptance[512..544].fill(5);
        acceptance[544..576].fill(6);
        acceptance[576..608].fill(7);

        for (offset, magic, version) in [(32, b"AOSCSE01", 1_u16), (256, b"AOSPSC02", 2_u16)] {
            let packet = &mut acceptance[offset..offset + 224];
            packet[..8].copy_from_slice(magic);
            packet[8..10].copy_from_slice(&version.to_be_bytes());
            packet[12..20].copy_from_slice(&1_u64.to_be_bytes());
            packet[20..36].copy_from_slice(project.as_bytes());
            packet[36..44].copy_from_slice(&2_u64.to_be_bytes());
            packet[44..76].fill(4);
            packet[76..108].fill(if version == 1 { 6 } else { 5 });
            packet[108..124].fill(8);
            packet[124..132].copy_from_slice(&1_u64.to_be_bytes());
            for (limit, value) in packet[132..160]
                .chunks_exact_mut(4)
                .zip([1_u32, 2, 1, 1, 1, 1, 1])
            {
                limit.copy_from_slice(&value.to_be_bytes());
            }
        }
        SourceTreeGenesisIntentContextV1::decode(&context).unwrap()
    }

    #[test]
    fn genesis_requests_keep_global_empty_distinct_from_populated_and_legacy_modes() {
        let empty = SourceTreeGenesisChallengeV1::new([1; 16], None).unwrap();
        let bytes = encode_genesis_request(empty, None, None).unwrap();
        assert_eq!(decode_genesis_request(&bytes).unwrap(), (empty, None, None));
        assert!(decode_request_mode(bytes[..REQUEST_BYTES].try_into().unwrap()).is_err());
        assert_eq!(bytes.len(), 736);
        assert_eq!(&bytes[..8], b"AOSSSR08");
        assert!(bytes[REQUEST_BYTES..].iter().all(|byte| *byte == 0));

        let project = ProjectId::from_bytes([2; 16]);
        let populated =
            SourceTreeGenesisChallengeV1::new([3; 16], Some(ObjectDigest::from_bytes([4; 32])))
                .unwrap();
        let context = genesis_context(project);
        let bytes = encode_genesis_request(populated, Some(project), Some(&context)).unwrap();
        assert_eq!(
            decode_genesis_request(&bytes).unwrap(),
            (populated, Some(project), Some(context.clone()))
        );
        assert!(encode_genesis_request(populated, None, Some(&context)).is_err());
        assert!(encode_genesis_request(empty, Some(project), Some(&context)).is_err());
        assert!(encode_genesis_request(populated, Some(project), None).is_err());
        assert!(encode_genesis_request(empty, None, Some(&context)).is_err());
        assert!(
            encode_genesis_request(
                populated,
                Some(project),
                Some(&genesis_context(ProjectId::from_bytes([5; 16])))
            )
            .is_err()
        );
        for range in [8..24, 24..56, 56..72, REQUEST_BYTES..REQUEST_GENESIS_BYTES] {
            let mut malformed = bytes;
            malformed[range].fill(0);
            assert!(decode_genesis_request(&malformed).is_err());
        }
        let mut foreign = bytes;
        foreign[..8].copy_from_slice(REQUEST_NAMES_MAGIC);
        assert!(decode_genesis_request(&foreign).is_err());
        foreign[..8].copy_from_slice(b"AOSSSR07");
        assert!(decode_genesis_request(&foreign).is_err());
        assert!(decode_request_mode(foreign[..REQUEST_BYTES].try_into().unwrap()).is_err());

        let mut empty = encode_genesis_request(empty, None, None).unwrap();
        empty[REQUEST_BYTES] = 1;
        assert!(decode_genesis_request(&empty).is_err());
    }

    #[test]
    fn genesis_replies_require_exact_domain_width_and_eof() {
        let payload = [7; SOURCE_TREE_GENESIS_READBACK_BYTES_V1];
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        write_framed_reply::<REPLY_GENESIS_BYTES>(&mut sender, REPLY_GENESIS_MAGIC, &payload)
            .unwrap();
        sender.shutdown(std::net::Shutdown::Write).unwrap();
        assert_eq!(
            read_framed_reply::<REPLY_GENESIS_BYTES, SOURCE_TREE_GENESIS_READBACK_BYTES_V1>(
                &mut receiver,
                REPLY_GENESIS_MAGIC,
            )
            .unwrap(),
            payload
        );

        for mutation in 0..3 {
            let (mut sender, mut receiver) = UnixStream::pair().unwrap();
            let mut bytes = vec![7; REPLY_GENESIS_BYTES];
            bytes[..8].copy_from_slice(REPLY_GENESIS_MAGIC);
            match mutation {
                0 => bytes[..8].copy_from_slice(REPLY_COMPLETED_MAGIC),
                1 => {
                    bytes.pop();
                }
                _ => bytes.push(0),
            }
            sender.write_all(&bytes).unwrap();
            sender.shutdown(std::net::Shutdown::Write).unwrap();
            assert!(
                read_framed_reply::<REPLY_GENESIS_BYTES, SOURCE_TREE_GENESIS_READBACK_BYTES_V1>(
                    &mut receiver,
                    REPLY_GENESIS_MAGIC,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn framed_project_replies_require_exact_magic_length_and_eof() {
        let mut canonical = [0; REPLY_PROJECT_BYTES];
        canonical[..8].copy_from_slice(REPLY_PROJECT_MAGIC);
        canonical[8..].fill(7);
        let (mut client, mut server) = UnixStream::pair().unwrap();
        write_framed_reply::<REPLY_PROJECT_BYTES>(
            &mut client,
            REPLY_PROJECT_MAGIC,
            &[7; SOURCE_PROJECT_ADMISSION_READBACK_BYTES_V1],
        )
        .unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        assert_eq!(
            read_project_reply(&mut server).unwrap(),
            [7; SOURCE_PROJECT_ADMISSION_READBACK_BYTES_V1]
        );

        for changed in [
            {
                let mut changed = canonical.to_vec();
                changed[0] ^= 1;
                changed
            },
            canonical[..canonical.len() - 1].to_vec(),
            {
                let mut changed = canonical.to_vec();
                changed.push(1);
                changed
            },
        ] {
            let (mut client, mut server) = UnixStream::pair().unwrap();
            client.write_all(&changed).unwrap();
            client.shutdown(std::net::Shutdown::Write).unwrap();
            assert!(read_project_reply(&mut server).is_err());
        }

        let mut reservation = [0; REPLY_RESERVATION_BYTES];
        reservation[..8].copy_from_slice(REPLY_RESERVATION_MAGIC);
        let (mut client, mut server) = UnixStream::pair().unwrap();
        assert!(
            write_framed_reply::<REPLY_RESERVATION_BYTES>(
                &mut client,
                REPLY_RESERVATION_MAGIC,
                &[0; 1],
            )
            .is_err()
        );
        client.write_all(&reservation).unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        assert!(
            read_framed_reply::<
                REPLY_RESERVATION_BYTES,
                SOURCE_PROJECT_RESERVATION_READBACK_BYTES_V1,
            >(&mut server, REPLY_RESERVATION_MAGIC,)
            .is_ok()
        );
    }

    #[test]
    fn request_frame_rejects_foreign_and_noncanonical_source_claims() {
        let challenge =
            SourceHoldReadbackChallengeV1::new([1; 16], ObjectDigest::from_bytes([2; 32]))
                .expect("challenge");
        let project = ProjectId::from_bytes([3; 16]);
        let bytes = encode_request(challenge, project);
        assert_eq!(
            decode_request(&bytes).expect("canonical request"),
            (challenge, project)
        );
        let mut names = bytes;
        names[..8].copy_from_slice(REQUEST_NAMES_MAGIC);
        assert_eq!(
            decode_request_mode(&names).expect("names request"),
            (challenge, project, SourceSignerRequestModeV1::HeldNames)
        );
        let mut project_admission = bytes;
        project_admission[..8].copy_from_slice(REQUEST_PROJECT_MAGIC);
        assert_eq!(
            decode_request_mode(&project_admission).expect("project admission request"),
            (
                challenge,
                project,
                SourceSignerRequestModeV1::ProjectAdmission
            )
        );
        let mut retirement = bytes;
        retirement[..8].copy_from_slice(REQUEST_RETIREMENT_MAGIC);
        assert_eq!(
            decode_request_mode(&retirement).expect("project retirement request"),
            (
                challenge,
                project,
                SourceSignerRequestModeV1::ProjectRetirement
            )
        );
        let mut reservation = bytes;
        reservation[..8].copy_from_slice(REQUEST_RESERVATION_MAGIC);
        assert_eq!(
            decode_request_mode(&reservation).expect("project reservation request"),
            (
                challenge,
                project,
                SourceSignerRequestModeV1::ProjectReservation
            )
        );
        let mut completed = bytes;
        completed[..8].copy_from_slice(REQUEST_COMPLETED_MAGIC);
        assert_eq!(
            decode_request_mode(&completed).unwrap(),
            (
                challenge,
                project,
                SourceSignerRequestModeV1::ProjectCompletedTerminal
            )
        );
        completed[8..24].fill(0);
        assert!(decode_request_mode(&completed).is_err());

        let mut foreign = bytes;
        foreign[..8].copy_from_slice(b"AOSCSC02");
        assert!(decode_request(&foreign).is_err());
        assert!(decode_request_mode(&foreign).is_err());
        let mut zero_project = bytes;
        zero_project[56..72].fill(0);
        assert!(decode_request(&zero_project).is_err());
        let mut zero_nonce = bytes;
        zero_nonce[8..24].fill(0);
        assert!(decode_request(&zero_nonce).is_err());
        names[8..24].fill(0);
        assert!(decode_request_mode(&names).is_err());
    }

    #[test]
    fn names_reply_requires_distinct_version_and_exact_eof() {
        let read = |magic: &[u8; 8], extra: &[u8]| {
            let (mut root, mut signer) = UnixStream::pair().expect("Source signer pair");
            let mut reply = [0; REPLY_NAMES_BYTES];
            reply[..8].copy_from_slice(magic);
            signer.write_all(&reply).expect("reply");
            signer.write_all(extra).expect("extra");
            signer.shutdown(std::net::Shutdown::Write).expect("EOF");
            read_names_reply(&mut root)
        };
        assert!(read(REPLY_NAMES_MAGIC, &[]).is_ok());
        assert!(read(REPLY_MAGIC, &[]).is_err());
        assert!(read(REPLY_NAMES_MAGIC, &[1]).is_err());
    }

    #[test]
    fn completed_terminal_reply_rejects_pending_domain_width_and_trailing_bytes() {
        let read = |bytes: &[u8]| {
            let (mut root, mut signer) = UnixStream::pair().unwrap();
            signer.write_all(bytes).unwrap();
            signer.shutdown(std::net::Shutdown::Write).unwrap();
            read_framed_reply::<
                REPLY_COMPLETED_BYTES,
                SOURCE_PROJECT_COMPLETED_TERMINAL_READBACK_BYTES_V1,
            >(&mut root, REPLY_COMPLETED_MAGIC)
        };
        let mut completed = [0; REPLY_COMPLETED_BYTES];
        completed[..8].copy_from_slice(REPLY_COMPLETED_MAGIC);
        completed[8..].fill(7);
        assert_eq!(
            read(&completed).unwrap(),
            [7; SOURCE_PROJECT_COMPLETED_TERMINAL_READBACK_BYTES_V1]
        );
        let mut pending_domain = completed;
        pending_domain[..8].copy_from_slice(REPLY_PROJECT_MAGIC);
        assert!(read(&pending_domain).is_err());
        assert!(read(&completed[..completed.len() - 1]).is_err());
        assert!(read(&[completed.as_slice(), &[1]].concat()).is_err());
    }
}
