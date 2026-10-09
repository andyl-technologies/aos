//! Canonical environment activation transaction records.
//!
//! ```text
//! AOSENVA1 | version:u16 | phase:u8 | reserved:5 |
//! transaction:16 | project:16 | sandbox:16 | revision:u64 |
//! predecessor-present:u8 | reserved:7 | predecessor:32 |
//! desired-selector | current-selector-slot | observed-selector-slot |
//! lease-count:u32 | leases | root-count:u32 | roots |
//! retained-count:u32 | retained-selectors | digest:32
//! ```
//!
//! Selectors contain only `generation:u64 | manifest-digest:32`; decoding
//! resolves them through a replay-validated manifest history. This prevents an
//! activation record from inventing a facade or closure beside a real digest.

use aos_sandbox_core::{
    ExecutionId, MediaType, ObjectDescriptor, ObjectDigest, ProjectId, ResourceId, Revision,
    SandboxId, SnapshotId,
};
use sha2::{Digest as _, Sha256};

use super::{
    EnvironmentActivationPhaseV1, EnvironmentActivationTransactionV1,
    EnvironmentGcRootAcknowledgementV1, EnvironmentGenerationHistoryV1,
    EnvironmentGenerationLeaseStatusV1, EnvironmentGenerationLeaseV1, EnvironmentLeaseConsumerV1,
    EnvironmentLeaseTimeV1, EnvironmentManifestDigestV1, EnvironmentModelError,
    EnvironmentSelectorV1, MAXIMUM_ENVIRONMENT_INPUTS,
};

const MAGIC: &[u8; 8] = b"AOSENVA1";
const VERSION: u16 = 1;
const DOMAIN: &[u8] = b"aos.sandbox.environment.activation-record.v1\0";
const MAXIMUM_ACTIVATION_RECORD_BYTES: usize = 32 * 1024 * 1024;
const SELECTOR_BYTES: usize = 40;
const OPTIONAL_SELECTOR_BYTES: usize = 48;
const LEASE_BYTES: usize = 145;
const DIGEST_BYTES: usize = 32;

/// Encodes one validated activation transaction with a checked allocation.
///
/// # Errors
///
/// Returns [`EnvironmentModelError`] if its exact encoded size exceeds the
/// fixed ceiling, cannot be represented, or allocation fails.
pub fn encode_environment_activation_v1(
    value: &EnvironmentActivationTransactionV1,
) -> Result<Vec<u8>, EnvironmentModelError> {
    let length = activation_encoded_length(value)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| EnvironmentModelError::Allocation)?;
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.push(value.phase() as u8);
    bytes.extend_from_slice(&[0; 5]);
    bytes.extend_from_slice(value.transaction().as_bytes());
    bytes.extend_from_slice(value.project().as_bytes());
    bytes.extend_from_slice(value.sandbox().as_bytes());
    bytes.extend_from_slice(&value.revision().get().to_be_bytes());
    encode_optional_digest(&mut bytes, value.predecessor_record());
    encode_selector(&mut bytes, value.desired());
    encode_optional_selector(&mut bytes, value.current());
    encode_optional_selector(&mut bytes, value.observed());
    push_count(&mut bytes, value.leases().len())?;
    for lease in value.leases() {
        match lease.consumer() {
            EnvironmentLeaseConsumerV1::Execution(id) => {
                bytes.push(1);
                bytes.extend_from_slice(id.as_bytes());
            }
            EnvironmentLeaseConsumerV1::Snapshot(id) => {
                bytes.push(2);
                bytes.extend_from_slice(id.as_bytes());
            }
        }
        bytes.extend_from_slice(&lease.generation().get().to_be_bytes());
        bytes.extend_from_slice(lease.lease().as_bytes());
        bytes.extend_from_slice(&lease.revision().get().to_be_bytes());
        bytes.extend_from_slice(lease.boot().digest().as_bytes());
        bytes.extend_from_slice(&lease.observed_at().get().to_be_bytes());
        bytes.extend_from_slice(&lease.expires_at().to_be_bytes());
        bytes.push(lease.status() as u8);
        bytes.extend_from_slice(&[0; 7]);
        bytes.extend_from_slice(
            &lease
                .closed_at()
                .map_or(0, EnvironmentLeaseTimeV1::get)
                .to_be_bytes(),
        );
        bytes.extend_from_slice(
            lease
                .predecessor_boot()
                .map_or(ObjectDigest::from_bytes([0; 32]), |boot| boot.digest())
                .as_bytes(),
        );
    }
    push_count(&mut bytes, value.gc_roots().len())?;
    for root in value.gc_roots() {
        bytes.extend_from_slice(&root.generation().get().to_be_bytes());
        encode_descriptor(&mut bytes, root.descriptor())?;
        bytes.extend_from_slice(root.root().as_bytes());
        bytes.extend_from_slice(&root.revision().get().to_be_bytes());
        bytes.extend_from_slice(root.receipt().as_bytes());
    }
    push_count(&mut bytes, value.retained_old_generations().len())?;
    for selector in value.retained_old_generations() {
        encode_selector(&mut bytes, selector);
    }
    let digest = activation_digest(&bytes);
    bytes.extend_from_slice(digest.as_bytes());
    if bytes.len() != length {
        return Err(EnvironmentModelError::InvalidModel);
    }
    Ok(bytes)
}

/// Decodes one bounded activation record against retained canonical manifests.
///
/// # Errors
///
/// Returns [`EnvironmentModelError`] for malformed input, exhausted bounds,
/// unknown selector lineage, allocation failure, or a digest mismatch.
pub fn decode_environment_activation_v1(
    encoded: &[u8],
    manifests: &EnvironmentGenerationHistoryV1,
) -> Result<EnvironmentActivationTransactionV1, EnvironmentModelError> {
    preflight(encoded)?;
    let (body, stored_digest) = encoded.split_at(encoded.len() - DIGEST_BYTES);
    if activation_digest(body).as_bytes() != stored_digest {
        return Err(EnvironmentModelError::CorruptEncoding);
    }
    let mut bytes = body;
    if take::<8>(&mut bytes)? != *MAGIC || u16::from_be_bytes(take(&mut bytes)?) != VERSION {
        return Err(EnvironmentModelError::CorruptEncoding);
    }
    let phase = decode_phase(take::<1>(&mut bytes)?[0])?;
    if take::<5>(&mut bytes)? != [0; 5] {
        return Err(EnvironmentModelError::CorruptEncoding);
    }
    let transaction = ResourceId::from_bytes(take(&mut bytes)?);
    let project = ProjectId::from_bytes(take(&mut bytes)?);
    let sandbox = SandboxId::from_bytes(take(&mut bytes)?);
    let revision = Revision::new(u64::from_be_bytes(take(&mut bytes)?));
    let predecessor = decode_optional_digest(&mut bytes)?;
    let desired = decode_selector(&mut bytes, manifests, sandbox)?;
    let current = decode_optional_selector(&mut bytes, manifests, sandbox)?;
    let observed = decode_optional_selector(&mut bytes, manifests, sandbox)?;

    let lease_count = read_count(&mut bytes)?;
    let mut leases = Vec::new();
    leases
        .try_reserve_exact(lease_count)
        .map_err(|_| EnvironmentModelError::Allocation)?;
    for _ in 0..lease_count {
        let kind = take::<1>(&mut bytes)?[0];
        let identity = take(&mut bytes)?;
        let consumer = match kind {
            1 => EnvironmentLeaseConsumerV1::Execution(ExecutionId::from_bytes(identity)),
            2 => EnvironmentLeaseConsumerV1::Snapshot(SnapshotId::from_bytes(identity)),
            _ => return Err(EnvironmentModelError::CorruptEncoding),
        };
        let generation = Revision::new(u64::from_be_bytes(take(&mut bytes)?));
        let lease = ResourceId::from_bytes(take(&mut bytes)?);
        let revision = Revision::new(u64::from_be_bytes(take(&mut bytes)?));
        let boot =
            super::EnvironmentBootIdV1::from_stored(ObjectDigest::from_bytes(take(&mut bytes)?))?;
        let observed_at =
            super::EnvironmentLeaseTimeV1::from_stored(u64::from_be_bytes(take(&mut bytes)?))?;
        let expires_at = u64::from_be_bytes(take(&mut bytes)?);
        let status = match take::<1>(&mut bytes)?[0] {
            1 => EnvironmentGenerationLeaseStatusV1::Active,
            2 => EnvironmentGenerationLeaseStatusV1::Invalidated,
            _ => return Err(EnvironmentModelError::CorruptEncoding),
        };
        if take::<7>(&mut bytes)? != [0; 7] {
            return Err(EnvironmentModelError::CorruptEncoding);
        }
        let closed_raw = u64::from_be_bytes(take(&mut bytes)?);
        let closed_at = (closed_raw != 0)
            .then(|| super::EnvironmentLeaseTimeV1::from_stored(closed_raw))
            .transpose()?;
        let predecessor_raw = ObjectDigest::from_bytes(take(&mut bytes)?);
        let predecessor_boot = (predecessor_raw.as_bytes() != &[0; 32])
            .then(|| super::EnvironmentBootIdV1::from_stored(predecessor_raw))
            .transpose()?;
        leases.push(EnvironmentGenerationLeaseV1::from_stored(
            consumer,
            generation,
            lease,
            revision,
            boot,
            observed_at,
            expires_at,
            status,
            closed_at,
            predecessor_boot,
        )?);
    }
    let root_count = read_count(&mut bytes)?;
    let mut roots = Vec::new();
    roots
        .try_reserve_exact(root_count)
        .map_err(|_| EnvironmentModelError::Allocation)?;
    for _ in 0..root_count {
        roots.push(EnvironmentGcRootAcknowledgementV1::new(
            Revision::new(u64::from_be_bytes(take(&mut bytes)?)),
            decode_descriptor(&mut bytes)?,
            ResourceId::from_bytes(take(&mut bytes)?),
            Revision::new(u64::from_be_bytes(take(&mut bytes)?)),
            ObjectDigest::from_bytes(take(&mut bytes)?),
        )?);
    }
    let retained_count = read_count(&mut bytes)?;
    let mut retained = Vec::new();
    retained
        .try_reserve_exact(retained_count)
        .map_err(|_| EnvironmentModelError::Allocation)?;
    for _ in 0..retained_count {
        retained.push(decode_selector(&mut bytes, manifests, sandbox)?);
    }
    if !bytes.is_empty() {
        return Err(EnvironmentModelError::CorruptEncoding);
    }
    EnvironmentActivationTransactionV1::from_stored(
        transaction,
        project,
        sandbox,
        revision,
        predecessor,
        desired,
        current,
        observed,
        leases,
        roots,
        retained,
        phase,
    )
    .map_err(|_| EnvironmentModelError::CorruptEncoding)
}

/// Returns the canonical record digest used by activation lineage.
///
/// # Errors
///
/// Returns [`EnvironmentModelError`] under the encoder's fixed ceilings.
pub fn environment_activation_digest_v1(
    value: &EnvironmentActivationTransactionV1,
) -> Result<ObjectDigest, EnvironmentModelError> {
    let encoded = encode_environment_activation_v1(value)?;
    Ok(ObjectDigest::from_bytes(
        encoded[encoded.len() - DIGEST_BYTES..]
            .try_into()
            .map_err(|_| EnvironmentModelError::CorruptEncoding)?,
    ))
}

pub(super) fn activation_encoded_length(
    value: &EnvironmentActivationTransactionV1,
) -> Result<usize, EnvironmentModelError> {
    let roots = value
        .gc_roots()
        .iter()
        .try_fold(0_usize, |total, root| {
            total
                .checked_add(106)?
                .checked_add(root.descriptor().media_type().as_str().len())
        })
        .ok_or(EnvironmentModelError::InvalidModel)?;
    let length = 112_usize
        .checked_add(SELECTOR_BYTES)
        .and_then(|value| value.checked_add(OPTIONAL_SELECTOR_BYTES * 2))
        .and_then(|value| value.checked_add(4))
        .and_then(|total| total.checked_add(value.leases().len().checked_mul(LEASE_BYTES)?))
        .and_then(|value| value.checked_add(4))
        .and_then(|total| total.checked_add(roots))
        .and_then(|value| value.checked_add(4))
        .and_then(|total| {
            total.checked_add(
                value
                    .retained_old_generations()
                    .len()
                    .checked_mul(SELECTOR_BYTES)?,
            )
        })
        .and_then(|value| value.checked_add(DIGEST_BYTES))
        .ok_or(EnvironmentModelError::InvalidModel)?;
    if length > MAXIMUM_ACTIVATION_RECORD_BYTES {
        Err(EnvironmentModelError::InvalidModel)
    } else {
        Ok(length)
    }
}

fn preflight(encoded: &[u8]) -> Result<(), EnvironmentModelError> {
    if encoded.len() < 112 + SELECTOR_BYTES + OPTIONAL_SELECTOR_BYTES * 2 + 12 + DIGEST_BYTES
        || encoded.len() > MAXIMUM_ACTIVATION_RECORD_BYTES
    {
        return Err(EnvironmentModelError::CorruptEncoding);
    }
    let mut bytes = &encoded[..encoded.len() - DIGEST_BYTES];
    take_slice(
        &mut bytes,
        112 + SELECTOR_BYTES + OPTIONAL_SELECTOR_BYTES * 2,
    )?;
    let leases = read_count(&mut bytes)?;
    take_slice(
        &mut bytes,
        leases
            .checked_mul(LEASE_BYTES)
            .ok_or(EnvironmentModelError::CorruptEncoding)?,
    )?;
    let roots = read_count(&mut bytes)?;
    for _ in 0..roots {
        take_slice(&mut bytes, 8)?;
        preflight_descriptor(&mut bytes)?;
        take_slice(&mut bytes, 56)?;
    }
    let retained = read_count(&mut bytes)?;
    take_slice(
        &mut bytes,
        retained
            .checked_mul(SELECTOR_BYTES)
            .ok_or(EnvironmentModelError::CorruptEncoding)?,
    )?;
    if bytes.is_empty() {
        Ok(())
    } else {
        Err(EnvironmentModelError::CorruptEncoding)
    }
}

fn encode_selector(bytes: &mut Vec<u8>, value: &EnvironmentSelectorV1) {
    bytes.extend_from_slice(&value.generation().get().to_be_bytes());
    bytes.extend_from_slice(value.manifest().digest().as_bytes());
}

fn decode_selector(
    bytes: &mut &[u8],
    manifests: &EnvironmentGenerationHistoryV1,
    sandbox: SandboxId,
) -> Result<EnvironmentSelectorV1, EnvironmentModelError> {
    let generation = Revision::new(u64::from_be_bytes(take(bytes)?));
    let digest = EnvironmentManifestDigestV1::from_stored(ObjectDigest::from_bytes(take(bytes)?))?;
    manifests
        .selector_exact(sandbox, generation, digest)
        .map_err(|_| EnvironmentModelError::CorruptEncoding)?
        .ok_or(EnvironmentModelError::CorruptEncoding)
}

fn encode_optional_selector(bytes: &mut Vec<u8>, value: Option<&EnvironmentSelectorV1>) {
    bytes.push(u8::from(value.is_some()));
    bytes.extend_from_slice(&[0; 7]);
    if let Some(value) = value {
        encode_selector(bytes, value);
    } else {
        bytes.extend_from_slice(&[0; SELECTOR_BYTES]);
    }
}

fn decode_optional_selector(
    bytes: &mut &[u8],
    manifests: &EnvironmentGenerationHistoryV1,
    sandbox: SandboxId,
) -> Result<Option<EnvironmentSelectorV1>, EnvironmentModelError> {
    let present = take::<1>(bytes)?[0];
    if take::<7>(bytes)? != [0; 7] {
        return Err(EnvironmentModelError::CorruptEncoding);
    }
    match present {
        0 if take_slice(bytes, SELECTOR_BYTES)? == [0; SELECTOR_BYTES] => Ok(None),
        1 => decode_selector(bytes, manifests, sandbox).map(Some),
        _ => Err(EnvironmentModelError::CorruptEncoding),
    }
}

fn encode_optional_digest(bytes: &mut Vec<u8>, value: Option<ObjectDigest>) {
    bytes.push(u8::from(value.is_some()));
    bytes.extend_from_slice(&[0; 7]);
    bytes.extend_from_slice(
        value
            .unwrap_or_else(|| ObjectDigest::from_bytes([0; 32]))
            .as_bytes(),
    );
}

fn decode_optional_digest(
    bytes: &mut &[u8],
) -> Result<Option<ObjectDigest>, EnvironmentModelError> {
    let present = take::<1>(bytes)?[0];
    if take::<7>(bytes)? != [0; 7] {
        return Err(EnvironmentModelError::CorruptEncoding);
    }
    let digest = ObjectDigest::from_bytes(take(bytes)?);
    match present {
        0 if digest.as_bytes() == &[0; 32] => Ok(None),
        1 if digest.as_bytes() != &[0; 32] => Ok(Some(digest)),
        _ => Err(EnvironmentModelError::CorruptEncoding),
    }
}

fn encode_descriptor(
    bytes: &mut Vec<u8>,
    value: &ObjectDescriptor,
) -> Result<(), EnvironmentModelError> {
    let media = value.media_type().as_str().as_bytes();
    let length = u16::try_from(media.len()).map_err(|_| EnvironmentModelError::InvalidModel)?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(media);
    bytes.extend_from_slice(value.digest().as_bytes());
    bytes.extend_from_slice(&value.encoded_size().to_be_bytes());
    Ok(())
}

fn decode_descriptor(bytes: &mut &[u8]) -> Result<ObjectDescriptor, EnvironmentModelError> {
    let length = usize::from(u16::from_be_bytes(take(bytes)?));
    if length == 0 || length > 255 {
        return Err(EnvironmentModelError::CorruptEncoding);
    }
    let media = std::str::from_utf8(take_slice(bytes, length)?)
        .map_err(|_| EnvironmentModelError::CorruptEncoding)?;
    let media =
        MediaType::new(media.to_owned()).map_err(|_| EnvironmentModelError::CorruptEncoding)?;
    Ok(ObjectDescriptor::new(
        media,
        ObjectDigest::from_bytes(take(bytes)?),
        u64::from_be_bytes(take(bytes)?),
    ))
}

fn preflight_descriptor(bytes: &mut &[u8]) -> Result<(), EnvironmentModelError> {
    let length = usize::from(u16::from_be_bytes(take(bytes)?));
    if length == 0 || length > 255 {
        return Err(EnvironmentModelError::CorruptEncoding);
    }
    take_slice(
        bytes,
        length
            .checked_add(40)
            .ok_or(EnvironmentModelError::CorruptEncoding)?,
    )?;
    Ok(())
}

fn read_count(bytes: &mut &[u8]) -> Result<usize, EnvironmentModelError> {
    let count = usize::try_from(u32::from_be_bytes(take(bytes)?))
        .map_err(|_| EnvironmentModelError::CorruptEncoding)?;
    if count > MAXIMUM_ENVIRONMENT_INPUTS {
        Err(EnvironmentModelError::CorruptEncoding)
    } else {
        Ok(count)
    }
}

fn push_count(bytes: &mut Vec<u8>, value: usize) -> Result<(), EnvironmentModelError> {
    bytes.extend_from_slice(
        &u32::try_from(value)
            .map_err(|_| EnvironmentModelError::InvalidModel)?
            .to_be_bytes(),
    );
    Ok(())
}

fn decode_phase(value: u8) -> Result<EnvironmentActivationPhaseV1, EnvironmentModelError> {
    match value {
        1 => Ok(EnvironmentActivationPhaseV1::Desired),
        2 => Ok(EnvironmentActivationPhaseV1::Prepared),
        3 => Ok(EnvironmentActivationPhaseV1::Committed),
        4 => Ok(EnvironmentActivationPhaseV1::Observed),
        5 => Ok(EnvironmentActivationPhaseV1::Released),
        _ => Err(EnvironmentModelError::CorruptEncoding),
    }
}

fn activation_digest(bytes: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(DOMAIN)
            .chain_update(bytes)
            .finalize()
            .into(),
    )
}

fn take<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N], EnvironmentModelError> {
    take_slice(bytes, N)?
        .try_into()
        .map_err(|_| EnvironmentModelError::CorruptEncoding)
}

fn take_slice<'a>(bytes: &mut &'a [u8], count: usize) -> Result<&'a [u8], EnvironmentModelError> {
    let (head, tail) = bytes
        .split_at_checked(count)
        .ok_or(EnvironmentModelError::CorruptEncoding)?;
    *bytes = tail;
    Ok(head)
}
