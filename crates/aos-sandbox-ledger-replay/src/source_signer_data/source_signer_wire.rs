//! Canonical passive Source signer wire framing shared by both service paths.
//!
//! The established fourteen positive wire families retain their exact widths,
//! canonical comparison decoders and reply discriminators. Source07 is absent;
//! Source16 is a refusal discriminator only. Nothing here opens a journal,
//! borrows a receiving ledger, observes a peer, signs or creates currentness.
//!
//! ```text
//! fixed request = purpose[8] | nonce[16] | comparison-digest[32] | project[16]
//! extended request = fixed request | complete purpose-specific context
//! reply = purpose-specific framing[8] | complete signed observation packet
//! ```

use std::io;
use std::time::Duration;

use aos_sandbox_core::{ObjectDigest, ProjectId};

use crate::replay::phase_records::{
    RootFirstSourceSuccessorIntentV2,
};
use super::{
    SOURCE_FIRST_SUCCESSOR_READBACK_BYTES_V2, SOURCE_HOLD_READBACK_BYTES_V1, SOURCE_HOLD_READBACK_BYTES_V2, SOURCE_PROJECT_ADMISSION_READBACK_BYTES_V1, SOURCE_PROJECT_COMPLETED_TERMINAL_READBACK_BYTES_V1, SOURCE_PROJECT_RESERVATION_READBACK_BYTES_V1, SOURCE_PROJECT_RESOURCE_GENESIS_READBACK_BYTES_V4, SOURCE_TREE_GENESIS_INTENT_CONTEXT_BYTES_V1, SOURCE_TREE_GENESIS_INTENT_CONTEXT_BYTES_V2, SOURCE_TREE_GENESIS_READBACK_BYTES_V1, SourceHoldReadbackChallengeV1, SourceProjectGenesisChallengeV3, SourceTreeGenesisChallengeV1, SourceTreeGenesisIntentContextV1,
};

#[doc(hidden)]
pub use aos_sandbox_broker::source_signer_connection::{SourceSignerSocketCustodyOriginalsV1, require_source_signer_socket_custody_v1, SOURCE_SIGNER_SOCKET_PATH_V1};


/// Identifies the exact request magic framing.
pub const REQUEST_MAGIC: &[u8; 8] = b"AOSSSR01";
/// Identifies the exact reply magic framing.
pub const REPLY_MAGIC: &[u8; 8] = b"AOSSSP01";
/// Identifies the exact request names magic framing.
pub const REQUEST_NAMES_MAGIC: &[u8; 8] = b"AOSSSR02";
/// Identifies the exact reply names magic framing.
pub const REPLY_NAMES_MAGIC: &[u8; 8] = b"AOSSSP02";
/// Identifies the exact request project magic framing.
pub const REQUEST_PROJECT_MAGIC: &[u8; 8] = b"AOSSSR03";
/// Identifies the exact reply project magic framing.
pub const REPLY_PROJECT_MAGIC: &[u8; 8] = b"AOSSSP03";
/// Identifies the exact request retirement magic framing.
pub const REQUEST_RETIREMENT_MAGIC: &[u8; 8] = b"AOSSSR04";
/// Identifies the exact reply retirement magic framing.
pub const REPLY_RETIREMENT_MAGIC: &[u8; 8] = b"AOSSSP04";
/// Identifies the exact request reservation magic framing.
pub const REQUEST_RESERVATION_MAGIC: &[u8; 8] = b"AOSSSR05";
/// Identifies the exact reply reservation magic framing.
pub const REPLY_RESERVATION_MAGIC: &[u8; 8] = b"AOSSSP05";
/// Identifies the exact request completed magic framing.
pub const REQUEST_COMPLETED_MAGIC: &[u8; 8] = b"AOSSSR06";
/// Identifies the exact reply completed magic framing.
pub const REPLY_COMPLETED_MAGIC: &[u8; 8] = b"AOSSSP06";
/// Identifies the exact request genesis magic framing.
pub const REQUEST_GENESIS_MAGIC: &[u8; 8] = b"AOSSSR08";
/// Identifies the exact reply genesis magic framing.
pub const REPLY_GENESIS_MAGIC: &[u8; 8] = b"AOSSSP08";
/// Identifies the exact request first successor magic framing.
pub const REQUEST_FIRST_SUCCESSOR_MAGIC: &[u8; 8] = b"AOSSSR09";
/// Identifies the exact reply first successor magic framing.
pub const REPLY_FIRST_SUCCESSOR_MAGIC: &[u8; 8] = b"AOSSSP09";
/// Identifies the exact request project continuation magic framing.
pub const REQUEST_PROJECT_CONTINUATION_MAGIC: &[u8; 8] = b"AOSSSR10";
/// Identifies the exact reply project continuation magic framing.
pub const REPLY_PROJECT_CONTINUATION_MAGIC: &[u8; 8] = b"AOSSSP10";
/// Identifies the exact request project genesis magic v3 framing.
pub const REQUEST_PROJECT_GENESIS_MAGIC_V3: &[u8; 8] = b"AOSSSR11";
/// Identifies the exact reply project genesis magic v3 framing.
pub const REPLY_PROJECT_GENESIS_MAGIC_V3: &[u8; 8] = b"AOSSSP11";
/// Identifies the exact request project resource genesis magic v4 framing.
pub const REQUEST_PROJECT_RESOURCE_GENESIS_MAGIC_V4: &[u8; 8] = b"AOSSSR12";
/// Identifies the exact reply project resource genesis magic v4 framing.
pub const REPLY_PROJECT_RESOURCE_GENESIS_MAGIC_V4: &[u8; 8] = b"AOSSSP12";
/// Specifies the exact request project resource genesis bytes v4 width.
pub const REQUEST_PROJECT_RESOURCE_GENESIS_BYTES_V4: usize = REQUEST_BYTES + SOURCE_TREE_GENESIS_INTENT_CONTEXT_BYTES_V2;
/// Specifies the exact reply project resource genesis bytes v4 width.
pub const REPLY_PROJECT_RESOURCE_GENESIS_BYTES_V4: usize = 8 + SOURCE_PROJECT_RESOURCE_GENESIS_READBACK_BYTES_V4;
/// Identifies the exact request resource genesis magic framing.
pub const REQUEST_RESOURCE_GENESIS_MAGIC: &[u8; 8] = b"AOSSSR13";
/// Identifies the exact reply resource genesis magic framing.
pub const REPLY_RESOURCE_GENESIS_MAGIC: &[u8; 8] = b"AOSSSP13";
/// Specifies the exact request first successor bytes width.
pub const REQUEST_FIRST_SUCCESSOR_BYTES: usize = REQUEST_BYTES + 1248;
/// Specifies the exact reply first successor bytes width.
pub const REPLY_FIRST_SUCCESSOR_BYTES: usize = 8 + SOURCE_FIRST_SUCCESSOR_READBACK_BYTES_V2;
/// Identifies the exact request resource successor magic v4 framing.
pub const REQUEST_RESOURCE_SUCCESSOR_MAGIC_V4: &[u8; 8] = b"AOSSSR14";
/// Identifies the exact reply resource successor magic v4 framing.
pub const REPLY_RESOURCE_SUCCESSOR_MAGIC_V4: &[u8; 8] = b"AOSSSP14";
/// Identifies the exact request resource continuation magic v5 framing.
pub const REQUEST_RESOURCE_CONTINUATION_MAGIC_V5: &[u8; 8] = b"AOSSSR15";
/// Identifies the exact reply resource continuation magic v5 framing.
pub const REPLY_RESOURCE_CONTINUATION_MAGIC_V5: &[u8; 8] = b"AOSSSP15";
/// Identifies the exact request current nix magic v1 framing.
pub const REQUEST_CURRENT_NIX_MAGIC_V1: &[u8; 8] = b"AOSSSR16";
/// Specifies the exact request resource successor bytes width.
pub const REQUEST_RESOURCE_SUCCESSOR_BYTES: usize = 72 + 1424;
/// Specifies the exact reply genesis bytes width.
pub const REPLY_GENESIS_BYTES: usize = 8 + SOURCE_TREE_GENESIS_READBACK_BYTES_V1;
/// Specifies the exact reply completed bytes width.
pub const REPLY_COMPLETED_BYTES: usize = 8 + SOURCE_PROJECT_COMPLETED_TERMINAL_READBACK_BYTES_V1;
/// Specifies the exact request bytes width.
pub const REQUEST_BYTES: usize = 72;
/// Specifies the exact request genesis bytes width.
pub const REQUEST_GENESIS_BYTES: usize = REQUEST_BYTES + SOURCE_TREE_GENESIS_INTENT_CONTEXT_BYTES_V1;
/// Specifies the exact reply bytes width.
pub const REPLY_BYTES: usize = 8 + SOURCE_HOLD_READBACK_BYTES_V1;
/// Specifies the exact reply names bytes width.
pub const REPLY_NAMES_BYTES: usize = 8 + SOURCE_HOLD_READBACK_BYTES_V2;
/// Specifies the exact reply project bytes width.
pub const REPLY_PROJECT_BYTES: usize = 8 + SOURCE_PROJECT_ADMISSION_READBACK_BYTES_V1;
/// Specifies the exact reply reservation bytes width.
pub const REPLY_RESERVATION_BYTES: usize = 8 + SOURCE_PROJECT_RESERVATION_READBACK_BYTES_V1;
/// Bounds one established Source transport flight without renewing an owner lifetime.
pub const FLIGHT_TIMEOUT: Duration = Duration::from_secs(5);
/// Encodes the legacy selected Project genesis comparison request.
///
/// # Errors
/// Rejects a foreign width, noncanonical comparison context, sentinel identity,
/// or failed original typed-context decode, preserving its existing error.
pub fn encode_project_genesis_request_v3(
    challenge: SourceProjectGenesisChallengeV3,
    context: &SourceTreeGenesisIntentContextV1,
) -> io::Result<[u8; REQUEST_GENESIS_BYTES]> {
    encode_project_genesis_request(challenge, context)
}

/// Encodes the exact legacy or resource Project genesis comparison request.
///
/// # Errors
/// Rejects a foreign width, noncanonical comparison context, sentinel identity,
/// or failed original typed-context decode, preserving its existing error.
pub fn encode_project_genesis_request<const BYTES: usize>(
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

/// Decodes and round-trips the selected Project genesis request.
///
/// # Errors
/// Rejects a foreign width, noncanonical comparison context, sentinel identity,
/// or failed original typed-context decode, preserving its existing error.
pub fn decode_project_genesis_request_v3(
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

/// Selects one established successor comparison framing recipe.
#[derive(Clone, Copy)]
pub enum SourceSuccessorRequestRecipe {
    /// Uses the legacy single-project successor recipe.
    SingleProjectV2,
    /// Uses the legacy mixed-project continuation recipe.
    MixedProjectsV3,
    /// Retains the complete resource single-project successor context.
    ResourceSingleProjectV4,
    /// Retains the complete resource mixed-project continuation context.
    ResourceMixedProjectsV5,
}

impl SourceSuccessorRequestRecipe {
    /// Returns the exact request framing discriminator.
    pub const fn request_magic(self) -> &'static [u8; 8] {
        match self {
            Self::SingleProjectV2 => REQUEST_FIRST_SUCCESSOR_MAGIC,
            Self::MixedProjectsV3 => REQUEST_PROJECT_CONTINUATION_MAGIC,
            Self::ResourceSingleProjectV4 => REQUEST_RESOURCE_SUCCESSOR_MAGIC_V4,
            Self::ResourceMixedProjectsV5 => REQUEST_RESOURCE_CONTINUATION_MAGIC_V5,
        }
    }

    /// Returns the exact reply framing discriminator.
    pub const fn reply_magic(self) -> &'static [u8; 8] {
        match self {
            Self::SingleProjectV2 => REPLY_FIRST_SUCCESSOR_MAGIC,
            Self::MixedProjectsV3 => REPLY_PROJECT_CONTINUATION_MAGIC,
            Self::ResourceSingleProjectV4 => REPLY_RESOURCE_SUCCESSOR_MAGIC_V4,
            Self::ResourceMixedProjectsV5 => REPLY_RESOURCE_CONTINUATION_MAGIC_V5,
        }
    }

    /// Reports whether the recipe retains complete resource authorization.
    pub const fn resource(self) -> bool {
        matches!(self, Self::ResourceSingleProjectV4 | Self::ResourceMixedProjectsV5)
    }
}

/// Encodes one exact complete resource successor comparison request.
///
/// # Errors
/// Rejects a foreign width, noncanonical comparison context, sentinel identity,
/// or failed original typed-context decode, preserving its existing error.
pub fn encode_resource_successor_request(
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

/// Encodes the legacy single-project successor comparison request.
///
/// # Panics
/// Panics when supplied a resource-width context to this legacy-width encoder.
pub fn encode_first_successor_request(fresh_nonce: [u8; 16], context: &RootFirstSourceSuccessorIntentV2) -> [u8; REQUEST_FIRST_SUCCESSOR_BYTES] {
    encode_source_successor_request(fresh_nonce, context, SourceSuccessorRequestRecipe::SingleProjectV2)
}

/// Encodes the selected legacy successor comparison recipe.
///
/// # Panics
/// Panics when supplied a resource-width context to this legacy-width encoder.
pub fn encode_source_successor_request(
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

/// Decodes and round-trips the legacy single-project successor request.
///
/// # Errors
/// Rejects a foreign width, noncanonical comparison context, sentinel identity,
/// or failed original typed-context decode, preserving its existing error.
pub fn decode_first_successor_request(request: &[u8; REQUEST_FIRST_SUCCESSOR_BYTES])
    -> io::Result<([u8; 16], RootFirstSourceSuccessorIntentV2)>
{
    decode_source_successor_request(request, SourceSuccessorRequestRecipe::SingleProjectV2)
}

/// Decodes and round-trips the selected legacy successor request.
///
/// # Errors
/// Rejects a foreign width, noncanonical comparison context, sentinel identity,
/// or failed original typed-context decode, preserving its existing error.
pub fn decode_source_successor_request(
    request: &[u8; REQUEST_FIRST_SUCCESSOR_BYTES], recipe: SourceSuccessorRequestRecipe,
) -> io::Result<([u8; 16], RootFirstSourceSuccessorIntentV2)> {
    let nonce: [u8; 16] = request[8..24].try_into().map_err(|_| invalid_data("invalid successor nonce"))?;
    let context = RootFirstSourceSuccessorIntentV2::decode(&request[72..]).map_err(crate::data::SourceSuccessorDataErrorV2::from).map_err(io::Error::other)?;
    if nonce == [0; 16] || encode_source_successor_request(nonce, &context, recipe) != *request {
        return Err(invalid_data("noncanonical first-successor signer request"));
    }
    Ok((nonce, context))
}

/// Encodes one legacy strict genesis comparison request.
///
/// # Errors
/// Rejects a foreign width, noncanonical comparison context, sentinel identity,
/// or failed original typed-context decode, preserving its existing error.
pub fn encode_genesis_request(
    challenge: SourceTreeGenesisChallengeV1,
    project: Option<ProjectId>,
    intent_context: Option<&SourceTreeGenesisIntentContextV1>,
) -> io::Result<[u8; REQUEST_GENESIS_BYTES]> {
    encode_strict_genesis_request(challenge, project, intent_context)
}

/// Encodes the selected strict genesis comparison request.
///
/// # Errors
/// Rejects a foreign width, noncanonical comparison context, sentinel identity,
/// or failed original typed-context decode, preserving its existing error.
pub fn encode_strict_genesis_request<const BYTES: usize>(
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

/// Decodes and round-trips a complete strict genesis comparison request.
///
/// # Errors
/// Rejects a foreign width, noncanonical comparison context, sentinel identity,
/// or failed original typed-context decode, preserving its existing error.
pub fn decode_genesis_request(
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

/// Encodes the fixed held Source comparison request.
pub fn encode_request(
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

/// Decodes the fixed held Source comparison request.
///
/// # Errors
/// Rejects a foreign width, noncanonical comparison context, sentinel identity,
/// or failed original typed-context decode, preserving its existing error.
pub fn decode_request(
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

/// Decodes the closed fixed-width Source signing purpose and challenge.
///
/// # Errors
/// Rejects a foreign width, noncanonical comparison context, sentinel identity,
/// or failed original typed-context decode, preserving its existing error.
pub fn decode_request_mode(
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

/// Selects one established fixed-width Source comparison purpose.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceSignerRequestModeV1 {
    /// Observes the current held Source head.
    Held,
    /// Observes the held Source head and exact fixed names.
    HeldNames,
    /// Observes the current typed project admission challenge.
    ProjectAdmission,
    /// Observes the exact unsettled retirement comparison without ancestry authority.
    ProjectRetirement,
    /// Observes the unconsumed project reservation and admission absence.
    ProjectReservation,
    /// Observes the exact completed project terminal.
    ProjectCompletedTerminal,
}

/// Creates the existing invalid-data error for a fixed Source wire refusal.
pub fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
