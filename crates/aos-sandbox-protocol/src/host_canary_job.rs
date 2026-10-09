//! Decodes the independently signed fixed Host canary job as comparison DATA.
//!
//! This sole pure decoder is shared by Host, Storage and the runtime publisher.
//! It never captures a file, authenticates a peer, grants an effect or proves
//! currentness. The caller must retain and revalidate its own original carrier.
//!
//! ```text
//! AOSHCJ01 | header[968] | ten bounded segments | Ed25519 signature[64]
//! approval pin = stable key ID[16] | Ed25519 public key[32]
//! ```

use std::ops::Range;

use aos_proto::aos::sandbox::local::v1::{ApplyRuntimeRequest, RuntimeAction};
use buffa::Message as _;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest as _, Sha256};

use crate::{ValidatedRuntimeTemplateV1, decode_runtime_template_v1};

/// Exact fixed header width of the original signed job.
pub const HOST_CANARY_JOB_HEADER_BYTES: usize = 968;
/// Maximum complete signed job width, including all bounded segments.
pub const MAXIMUM_HOST_CANARY_JOB_BYTES: usize = 349_192;
const APPROVAL_PIN_BYTES: usize = 48;
const DOMAIN: &[u8] = b"aos.sandbox.host.canary-job.v1\0";
const SEGMENT_LIMITS: [usize; 10] = [
    65_536, 65_536, 65_536, 4_096, 65_536,
    4_096, 65_536, 4_096, 4_096, 4_096,
];

/// Reports a pure canonical-job or bounded allocation refusal.
#[derive(Debug, thiserror::Error)]
pub enum HostCanaryJobDataErrorV1 {
    /// The sole signature preimage could not be reserved.
    #[error("Host canary allocation could not be reserved")]
    Allocation,
    /// The signature, fixed grammar or internal comparison DATA is invalid.
    #[error("Host canary job signature or closed schema is invalid")]
    Job,
}

/// Preserves the complete canonical signed job projection without authority.
pub struct HostCanaryJobDataV1 {
    /// Preserves the independently signed digest comparison DATA.
    pub digest: [u8; 32],
    /// Preserves the independently signed job id comparison DATA.
    pub job_id: [u8; 16],
    /// Preserves the independently signed node id comparison DATA.
    pub node_id: [u8; 16],
    /// Preserves the independently signed boot id comparison DATA.
    pub boot_id: [u8; 16],
    /// Preserves the independently signed payload boot id comparison DATA.
    pub payload_boot_id: [u8; 16],
    /// Preserves the independently signed request ids comparison DATA.
    pub request_ids: [[u8; 16]; 3],
    /// Preserves the independently signed maximum response bytes comparison DATA.
    pub maximum_response_bytes: [u32; 2],
    /// Preserves the independently signed nonce comparison DATA.
    pub nonce: [u8; 32],
    /// Preserves the independently signed pins comparison DATA.
    pub pins: [[u8; 32]; 12],
    /// Preserves the independently signed guest public key comparison DATA.
    pub guest_public_key: [u8; 32],
    /// Preserves the independently signed attach public key comparison DATA.
    pub attach_public_key: [u8; 32],
    /// Preserves the independently signed maximum charges comparison DATA.
    pub maximum_charges: [u64; 22],
    /// Preserves the independently signed not before comparison DATA.
    pub not_before: u64,
    /// Preserves the independently signed deadline comparison DATA.
    pub deadline: u64,
    /// Preserves the independently signed approval generation comparison DATA.
    pub approval_generation: u64,
    /// Preserves the independently signed namespace generation comparison DATA.
    pub namespace_generation: u64,
    /// Preserves the independently signed launch comparison DATA.
    pub launch: ValidatedRuntimeTemplateV1,
    /// Preserves the independently signed stop comparison DATA.
    pub stop: ValidatedRuntimeTemplateV1,
    /// Preserves the independently signed segments comparison DATA.
    pub segments: [Range<usize>; 10],
}

/// Decodes the complete signed job against the independently supplied approval pin.
///
/// The returned fields are DATA; in particular signed boottime bounds are not a
/// clock or an effect permit. The original segment ranges borrow no live owner.
///
/// # Errors
///
/// Refuses unsupported widths, signatures, reserved fields, segment bounds,
/// template or identity crosslinks and failed preimage reservation.
pub fn decode_host_canary_job_v1(
    bytes: &[u8],
    approval: &[u8]
) -> std::result::Result<HostCanaryJobDataV1, HostCanaryJobDataErrorV1> {
    if bytes.len() < HOST_CANARY_JOB_HEADER_BYTES + 64 || bytes.len() > MAXIMUM_HOST_CANARY_JOB_BYTES
        || approval.len() != APPROVAL_PIN_BYTES || &bytes[..8] != b"AOSHCJ01"
        || field::<2>(bytes, 8)? != 1_u16.to_be_bytes()
        || field::<2>(bytes, 10)? != [0; 2]
        || u32::from_be_bytes(field(bytes, 12)?) != HOST_CANARY_JOB_HEADER_BYTES as u32
        || u32::from_be_bytes(field(bytes, 16)?) as usize != bytes.len()
        || field::<4>(bytes, 956)? != [0; 4]
        || bytes[892..908] != approval[..16] || approval[..16] == [0; 16]
    {
        return Err(HostCanaryJobDataErrorV1::Job);
    }

    let signed_end = bytes.len() - 64;
    let key = VerifyingKey::from_bytes(&field(approval, 16)?)
        .map_err(|_| HostCanaryJobDataErrorV1::Job)?;
    let mut preimage = Vec::new();
    preimage.try_reserve_exact(DOMAIN.len() + signed_end)
        .map_err(|_| HostCanaryJobDataErrorV1::Allocation)?;
    preimage.extend_from_slice(DOMAIN);
    preimage.extend_from_slice(&bytes[..signed_end]);
    key.verify_strict(&preimage, &Signature::from_bytes(&field(bytes, signed_end)?))
        .map_err(|_| HostCanaryJobDataErrorV1::Job)?;

    let mut segments: [Range<usize>; 10] = std::array::from_fn(|_| 0..0);
    let mut position = HOST_CANARY_JOB_HEADER_BYTES;
    for index in 0..10 {
        let length = u32::from_be_bytes(field(bytes, 916 + index * 4)?) as usize;
        if length == 0 || length > SEGMENT_LIMITS[index] {
            return Err(HostCanaryJobDataErrorV1::Job);
        }
        let end = position.checked_add(length).ok_or(HostCanaryJobDataErrorV1::Job)?;
        if end > signed_end {
            return Err(HostCanaryJobDataErrorV1::Job);
        }
        segments[index] = position..end;
        position = end;
    }
    if position != signed_end {
        return Err(HostCanaryJobDataErrorV1::Job);
    }

    let launch = decode_runtime_template_v1(&bytes[segments[0].clone()])
        .map_err(|_| HostCanaryJobDataErrorV1::Job)?;
    let stop = decode_runtime_template_v1(&bytes[segments[1].clone()])
        .map_err(|_| HostCanaryJobDataErrorV1::Job)?;
    let fence = launch.fence();
    if launch.action() != RuntimeAction::RUNTIME_ACTION_LAUNCH
        || stop.action() != RuntimeAction::RUNTIME_ACTION_STOP || stop.fence() != fence
        || *fence.sandbox_id() != field::<16>(bytes, 68)?
        || *fence.incarnation_id() != field::<16>(bytes, 84)?
        || fence.assignment_epoch() != u64::from_be_bytes(field(bytes, 116)?)
        || fence.desired_generation() != u64::from_be_bytes(field(bytes, 124)?)
        || *fence.assignment_digest() != field::<32>(bytes, 132)?
    {
        return Err(HostCanaryJobDataErrorV1::Job);
    }

    let boot_id = field(bytes, 52)?;
    let not_before = u64::from_be_bytes(field(bytes, 164)?);
    let deadline = u64::from_be_bytes(field(bytes, 172)?);
    let approval_generation = u64::from_be_bytes(field(bytes, 180)?);
    let namespace_generation = u64::from_be_bytes(field(bytes, 960)?);
    let request_ids = [field(bytes, 188)?, field(bytes, 204)?, field(bytes, 220)?];
    let mut maximum_response_bytes = [0; 2];
    for index in 0..2 {
        // The sole inert-template validator deliberately does not retain the
        // header. Borrow its already validated exact wire through the same
        // generated protobuf codec; this comparison creates no live request.
        let template = ApplyRuntimeRequest::decode_from_slice(&bytes[segments[index].clone()])
            .map_err(|_| HostCanaryJobDataErrorV1::Job)?;
        let header = template.header.as_option().ok_or(HostCanaryJobDataErrorV1::Job)?;
        if header.request_id.as_slice() != request_ids[index]
            || header.maximum_response_bytes > 4096
        {
            return Err(HostCanaryJobDataErrorV1::Job);
        }
        maximum_response_bytes[index] = header.maximum_response_bytes;
    }
    let pins = std::array::from_fn(|index| {
        let mut pin = [0; 32];
        pin.copy_from_slice(&bytes[268 + index * 32..300 + index * 32]);
        pin
    });
    let maximum_charges = std::array::from_fn(|index| {
        let mut value = [0; 8];
        value.copy_from_slice(&bytes[716 + index * 8..724 + index * 8]);
        u64::from_be_bytes(value)
    });
    if deadline <= not_before
        || approval_generation == 0
        || namespace_generation == 0
        || approval_generation != u64::from_be_bytes(field(bytes, 908)?)
        || request_ids.iter().any(|id| *id == [0; 16])
        || request_ids[0] == request_ids[1] || request_ids[0] == request_ids[2]
        || request_ids[1] == request_ids[2] || pins.iter().any(|pin| *pin == [0; 32])
    {
        return Err(HostCanaryJobDataErrorV1::Job);
    }

    let job_id = field(bytes, 20)?;
    let node_id = field(bytes, 36)?;
    let payload_boot_id = field(bytes, 100)?;
    let nonce = field(bytes, 236)?;
    let guest_public_key = field(bytes, 652)?;
    let attach_public_key = field(bytes, 684)?;
    if job_id == [0; 16] || node_id == [0; 16] || payload_boot_id == [0; 16]
        || nonce == [0; 32] || guest_public_key == [0; 32]
        || attach_public_key == [0; 32] || guest_public_key == attach_public_key
    {
        return Err(HostCanaryJobDataErrorV1::Job);
    }

    Ok(HostCanaryJobDataV1 {
        digest: Sha256::digest(bytes).into(),
        job_id,
        node_id,
        boot_id,
        payload_boot_id,
        request_ids,
        maximum_response_bytes,
        nonce,
        pins,
        guest_public_key,
        attach_public_key,
        maximum_charges,
        not_before,
        deadline,
        approval_generation,
        namespace_generation,
        launch,
        stop,
        segments,
    })
}

fn field<const N: usize>(
    bytes: &[u8],
    offset: usize
) -> std::result::Result<[u8; N], HostCanaryJobDataErrorV1> {
    bytes.get(offset..offset + N).and_then(|value| value.try_into().ok())
        .ok_or(HostCanaryJobDataErrorV1::Job)
}
