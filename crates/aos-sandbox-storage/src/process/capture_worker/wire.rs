//! Closed records on the existing native-authenticated ZFS worker channel.
//!
//! The parent encodes a request only through its genuine fresh Capture owner
//! after State/output persistence. Child decoding remains DATA until the sole
//! inherited-worker branch establishes the native storaged context. No key or
//! generic command, path adoption, financial original or positive proof crosses
//! this protocol.
//!
//! ```text
//! AOSCWQ03 | v3 | source944 | attempt424 | managed-root | domains4
//!          | original-pool-guid | headroom | remaining-floor | prepaid-drain
//!          | verified60-admitted-pair48 | plan-expiry8 | lease-expiry8 | body-SHA256
//! ```

use super::super::*;
use super::AuthenticatedCaptureWorkerContextV3;
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_protocol::storage_capture_grant::StorageCaptureGrantSourceV2;
use crate::{ManagedDatasetRoot, StorageDomainsV1};
use crate::catalog_transition::execution_capture::CaptureDatasetRequirementV1;

const MAGIC: &[u8; 8] = b"AOSCWQ03";
const DOMAIN: &[u8] = b"aos.sandbox.storage.capture-worker-request.v3\0";
const VERSION: u16 = 3;
const ATTEMPT_BYTES: usize = 424;
const SOURCE_BYTES: usize = 944;
const MAXIMUM_NAME_BYTES: usize = 1024;

pub(super) struct CaptureWorkerRequestDataV3 {
    pub(super) source: StorageCaptureGrantSourceV2,
    pub(super) attempt: [u8; ATTEMPT_BYTES],
    pub(super) requirement: CaptureDatasetRequirementV1,
    pub(super) expected_pool_guid: u64,
    pub(super) metadata_headroom_bytes: u64,
    pub(super) minimum_remaining_bytes: u64,
    pub(super) request_digest: ObjectDigest,
    pub(super) prepaid_drain_ceiling: u64,
    pub(super) admitted_clock: aos_sandbox_core::RawPairedClockSample,
    pub(super) plan_expires_seconds: i64,
    pub(super) authority_expires_seconds: i64,
}

pub(in crate::process) fn selects_request(bytes: &[u8]) -> bool { bytes.starts_with(MAGIC) }

pub(in crate::process) fn encode_from_native_v3(
    native: &crate::execution_capture_zfs_worker::NativeCaptureCreateOriginalV3,
    prepaid_drain_ceiling: u64,
    destination: &mut Vec<u8>,
) -> Result<(), ZfsWorkerError> {
    if !destination.is_empty() || prepaid_drain_ceiling == 0 { return Err(ZfsWorkerError::Authority); }
    let (source, attempt, requirement, policy) = native.worker_dispatch_inputs_v3()
        .ok_or(ZfsWorkerError::Authority)?;
    let root = requirement.root();
    let domains = requirement.planned_dataset().domains();
    let names = root.pool().len().checked_add(root.dataset_prefix().len())
        .ok_or(ZfsWorkerError::Protocol("capture request size overflowed"))?;
    let maximum = 8 + 2 + SOURCE_BYTES + ATTEMPT_BYTES + 2 * 2 + 8 + 4 * 32 + 4 * 8 + 64 + 32;
    let capacity = names.checked_add(maximum)
        .filter(|bytes| *bytes <= MAXIMUM_REQUEST_BYTES)
        .ok_or(ZfsWorkerError::Protocol("capture request exceeds fixed worker bound"))?;
    destination.try_reserve_exact(capacity)
        .map_err(|_| ZfsWorkerError::Protocol("capture request allocation failed"))?;
    destination.extend_from_slice(MAGIC);
    destination.extend_from_slice(&VERSION.to_be_bytes());
    destination.extend_from_slice(source.canonical_bytes_v2());
    destination.extend_from_slice(attempt);
    for name in [root.pool(), root.dataset_prefix()] {
        if name.is_empty() || name.len() > MAXIMUM_NAME_BYTES {
            return Err(ZfsWorkerError::Authority);
        }
        let length = u16::try_from(name.len()).map_err(|_| ZfsWorkerError::Authority)?;
        destination.extend_from_slice(&length.to_be_bytes());
        destination.extend_from_slice(name.as_bytes());
    }
    destination.extend_from_slice(&root.guid().to_be_bytes());
    for digest in [domains.disclosure(), domains.encryption(), domains.accounting(), domains.retention()] {
        destination.extend_from_slice(digest.as_bytes());
    }
    for scalar in [policy.expected_pool_guid(), policy.metadata_headroom_bytes(), policy.minimum_remaining_bytes()] {
        destination.extend_from_slice(&scalar.to_be_bytes());
    }
    destination.extend_from_slice(&prepaid_drain_ceiling.to_be_bytes());
    // These are the actual verified60 comparison fields, not a reconstructed
    // grant. Only this genuine parent encodes them on the authenticated worker
    // channel; the child runs the existing broker clock checker over them.
    let lifetime = native.admission_v3().lifetime_v3();
    let admitted = lifetime.admitted_clock_v3();
    let effect = &lifetime.admission_v3().effect;
    destination.extend_from_slice(&admitted.provenance().as_bytes());
    destination.extend_from_slice(&admitted.host_boot_id());
    destination.extend_from_slice(&admitted.wall_seconds().to_be_bytes());
    destination.extend_from_slice(&admitted.boottime_nanoseconds().to_be_bytes());
    destination.extend_from_slice(&effect.plan_expires_seconds().to_be_bytes());
    destination.extend_from_slice(&effect.authority_expires_seconds().to_be_bytes());
    let digest = digest(destination);
    destination.extend_from_slice(digest.as_bytes());
    Ok(())
}

fn digest(bytes: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(Sha256::new().chain_update(DOMAIN).chain_update(bytes).finalize().into())
}

fn text(decoder: &mut Decoder<'_>) -> Result<String, ZfsWorkerError> {
    let length = usize::from(decoder.u16()?);
    if length == 0 || length > MAXIMUM_NAME_BYTES { return Err(ZfsWorkerError::Authority); }
    let bytes = decoder.take(length)?;
    if bytes.contains(&0) { return Err(ZfsWorkerError::Authority); }
    String::from_utf8(bytes.to_vec()).map_err(|_| ZfsWorkerError::Authority)
}

// This returns only DATA and is intentionally private to the authenticated
// worker child. There is no public DTO-to-Native-authority conversion.
pub(super) fn decode_request(bytes: &[u8]) -> Result<CaptureWorkerRequestDataV3, ZfsWorkerError> {
    if bytes.len() > MAXIMUM_REQUEST_BYTES || bytes.len() < 32 {
        return Err(ZfsWorkerError::Protocol("capture request exceeds fixed worker bound"));
    }
    let payload_length = bytes.len() - 32;
    let request_digest = digest(&bytes[..payload_length]);
    if request_digest.as_bytes() != &bytes[payload_length..] { return Err(ZfsWorkerError::Authority); }
    let mut decoder = Decoder::new(&bytes[..payload_length]);
    if decoder.take(8)? != MAGIC || decoder.u16()? != VERSION { return Err(ZfsWorkerError::Authority); }
    let source = StorageCaptureGrantSourceV2::from_canonical_bytes_v2(decoder.take(SOURCE_BYTES)?)
        .map_err(|_| ZfsWorkerError::Authority)?;
    let attempt = decoder.array()?;
    let pool = text(&mut decoder)?;
    let prefix = text(&mut decoder)?;
    let root = ManagedDatasetRoot::from_catalog(&pool, &prefix, decoder.u64()?)
        .map_err(|_| ZfsWorkerError::Authority)?;
    let domains = StorageDomainsV1::new(ObjectDigest::from_bytes(decoder.array()?),
        ObjectDigest::from_bytes(decoder.array()?), ObjectDigest::from_bytes(decoder.array()?),
        ObjectDigest::from_bytes(decoder.array()?)).map_err(|_| ZfsWorkerError::Authority)?;
    let expected_pool_guid = decoder.u64()?;
    let metadata_headroom_bytes = decoder.u64()?;
    let minimum_remaining_bytes = decoder.u64()?;
    let prepaid_drain_ceiling = decoder.u64()?;
    let provenance = aos_sandbox_core::RawClockProvenance::new_untrusted(decoder.array()?)
        .map_err(|_| ZfsWorkerError::Authority)?;
    let admitted_boot = decoder.array()?;
    let admitted_wall = i64::from_be_bytes(decoder.array()?);
    let admitted_boottime = decoder.u64()?;
    let admitted_clock = aos_sandbox_core::RawPairedClockSample::new_untrusted(
        provenance, admitted_boot, admitted_wall, admitted_boottime,
    ).map_err(|_| ZfsWorkerError::Authority)?;
    let plan_expires_seconds = i64::from_be_bytes(decoder.array()?);
    let authority_expires_seconds = i64::from_be_bytes(decoder.array()?);
    source.lifetime_v2().first_pre_spawn_clock_v2().validate_later_sample(admitted_clock)
        .map_err(|_| ZfsWorkerError::Authority)?;
    if plan_expires_seconds <= admitted_wall || authority_expires_seconds <= admitted_wall {
        return Err(ZfsWorkerError::Authority);
    }
    decoder.finish()?;
    let original = source.original_source_v1();
    let (allocation, headroom, floor) = original.space_policy();
    if expected_pool_guid == 0 || metadata_headroom_bytes == 0 || minimum_remaining_bytes == 0
        || prepaid_drain_ceiling == 0
        || metadata_headroom_bytes != headroom || minimum_remaining_bytes != floor
    { return Err(ZfsWorkerError::Authority); }
    let requirement = CaptureDatasetRequirementV1::new(original.settlement().execution(),
        original.settlement().create_operation(), original.output_claim_digest(),
        original.storage_create_operation(), root, domains, original.output_limits().0, allocation)
        .map_err(|_| ZfsWorkerError::Authority)?;
    Ok(CaptureWorkerRequestDataV3 { source, attempt, requirement,
        expected_pool_guid, metadata_headroom_bytes, minimum_remaining_bytes, request_digest, prepaid_drain_ceiling, admitted_clock,
        plan_expires_seconds, authority_expires_seconds })
}


const CREATED_MAGIC: &[u8; 8] = b"AOSCWC03";
pub(in crate::process) const CREATED_BYTES_V3: usize = 226;
const _: [(); CREATED_BYTES_V3] = [();
    aos_sandbox_linux::seqpacket::bounded::ZfsWorkerRecordKindV1::CaptureCreatedV3.maximum_payload_bytes()];

pub(super) fn encode_created_v3(
    context: &AuthenticatedCaptureWorkerContextV3<'_>,
    observed: &crate::catalog_transition::execution_capture::readback::CaptureCreatedDatasetReadbackV3,
) -> [u8; CREATED_BYTES_V3] {
    let mut bytes = [0; CREATED_BYTES_V3];
    bytes[..8].copy_from_slice(CREATED_MAGIC);
    bytes[8..10].copy_from_slice(&VERSION.to_be_bytes());
    bytes[10..42].copy_from_slice(context.request_digest_v3().as_bytes());
    bytes[42..74].copy_from_slice(context.source_v3().source_digest_v2().as_bytes());
    bytes[74..106].copy_from_slice(observed.attempt_digest.as_bytes());
    bytes[106..138].copy_from_slice(observed.record_digest.as_bytes());
    bytes[138..146].copy_from_slice(&observed.guid.to_be_bytes());
    bytes[146..178].copy_from_slice(observed.observation_digest.as_bytes());
    bytes[178..186].copy_from_slice(&observed.dataset_available_bytes.to_be_bytes());
    bytes[186..194].copy_from_slice(&observed.observed_headroom_bytes.to_be_bytes());
    let digest = digest(&bytes[..194]);
    bytes[194..].copy_from_slice(digest.as_bytes());
    bytes
}

pub(in crate::process) fn decode_created_data_v3(
    bytes: &[u8],
    request_bytes: &[u8],
    native: &crate::execution_capture_zfs_worker::NativeCaptureCreateOriginalV3,
) -> Result<crate::catalog_transition::execution_capture::readback::CaptureCreatedDatasetReadbackV3, ZfsWorkerError> {
    use crate::catalog_transition::execution_capture::readback::CaptureCreatedDatasetReadbackV3;
    let (source, _, _, _) = native.worker_dispatch_inputs_v3().ok_or(ZfsWorkerError::Authority)?;
    if bytes.len() != CREATED_BYTES_V3 || request_bytes.len() < 32 {
        return Err(ZfsWorkerError::Authority);
    }
    let mut decoder = Decoder::new(&bytes[..194]);
    if decoder.take(8)? != CREATED_MAGIC || decoder.u16()? != VERSION
        || decoder.take(32)? != &request_bytes[request_bytes.len() - 32..]
        || decoder.take(32)? != source.source_digest_v2().as_bytes()
        || digest(&bytes[..194]).as_bytes() != &bytes[194..]
    { return Err(ZfsWorkerError::Authority); }
    let observed = CaptureCreatedDatasetReadbackV3 {
        attempt_digest: ObjectDigest::from_bytes(decoder.array()?),
        record_digest: ObjectDigest::from_bytes(decoder.array()?),
        guid: decoder.u64()?,
        observation_digest: ObjectDigest::from_bytes(decoder.array()?),
        dataset_available_bytes: decoder.u64()?,
        observed_headroom_bytes: decoder.u64()?,
    };
    decoder.finish()?;
    if observed.attempt_digest.as_bytes() == &[0; 32]
        || observed.record_digest != source.original_source_v1().output_record_digest()
        || observed.guid == 0 || observed.observation_digest.as_bytes() == &[0; 32]
        || observed.dataset_available_bytes == 0 || observed.observed_headroom_bytes == 0
    { return Err(ZfsWorkerError::Authority); }
    Ok(observed)
}


const CATALOG_MAGIC: &[u8; 8] = b"AOSCWK03";
pub(in crate::process) const CATALOG_BYTES_V3: usize = 250;

pub(crate) struct CaptureWorkerCatalogDataV3 {
    pub(crate) catalog: crate::CatalogBindingV1,
    pub(crate) guid: u64,
    pub(crate) dataset_binding: ObjectDigest,
    pub(crate) physical_row_digest: ObjectDigest,
    pub(super) source: ObjectDigest,
    pub(super) request: ObjectDigest,
}

pub(in crate::process) fn encode_catalog_from_native_v3(
    native: &crate::execution_capture_zfs_worker::NativeCaptureCreateOriginalV3,
    request: &[u8],
    catalog: &crate::state::CaptureStateCatalogOriginalV3,
    physical: &crate::execution_output::CapturePhysicalBindingOriginalV3,
) -> Result<[u8; CATALOG_BYTES_V3], ZfsWorkerError> {
    let dataset = catalog.dataset_for_native_v3(native).ok_or(ZfsWorkerError::Authority)?;
    if request.len() < 32 { return Err(ZfsWorkerError::Authority); }
    let physical_row_digest = physical.row_digest_for_native_v3(native).ok_or(ZfsWorkerError::Authority)?;
    let mut bytes = [0; CATALOG_BYTES_V3];
    bytes[..8].copy_from_slice(CATALOG_MAGIC);
    bytes[8..10].copy_from_slice(&VERSION.to_be_bytes());
    bytes[10..42].copy_from_slice(&request[request.len() - 32..]);
    bytes[42..74].copy_from_slice(native.admission_v3().source_v3().source_digest_v2().as_bytes());
    bytes[74..106].copy_from_slice(native.durable_attempt_digest_v3().as_bytes());
    bytes[106..114].copy_from_slice(&dataset.catalog_v3().generation().to_be_bytes());
    bytes[114..146].copy_from_slice(dataset.catalog_v3().digest().as_bytes());
    bytes[146..154].copy_from_slice(&dataset.guid().to_be_bytes());
    bytes[154..186].copy_from_slice(dataset.binding().as_bytes());
    bytes[186..218].copy_from_slice(physical_row_digest.as_bytes());
    let check = digest(&bytes[..218]);
    bytes[218..].copy_from_slice(check.as_bytes());
    Ok(bytes)
}

pub(super) fn decode_catalog_data_v3(
    context: &AuthenticatedCaptureWorkerContextV3<'_>,
    observed: &crate::catalog_transition::execution_capture::readback::CaptureCreatedDatasetReadbackV3,
    bytes: &[u8],
) -> Result<CaptureWorkerCatalogDataV3, ZfsWorkerError> {
    if bytes.len() != CATALOG_BYTES_V3 || digest(&bytes[..218]).as_bytes() != &bytes[218..] {
        return Err(ZfsWorkerError::Authority);
    }
    let (_, _, _, _, durable, _, _) = crate::execution_output::capture_worker_inputs_v3(context)
        .map_err(|_| ZfsWorkerError::Authority)?;
    let mut decoder = Decoder::new(&bytes[..218]);
    if decoder.take(8)? != CATALOG_MAGIC || decoder.u16()? != VERSION
        || decoder.take(32)? != context.request_digest_v3().as_bytes()
        || decoder.take(32)? != context.source_v3().source_digest_v2().as_bytes()
        || decoder.take(32)? != durable.as_bytes()
    { return Err(ZfsWorkerError::Authority); }
    let generation = decoder.u64()?;
    let head = ObjectDigest::from_bytes(decoder.array()?);
    let guid = decoder.u64()?;
    let dataset_binding = ObjectDigest::from_bytes(decoder.array()?);
    let physical_row_digest = ObjectDigest::from_bytes(decoder.array()?);
    decoder.finish()?;
    if guid == 0 || guid != observed.guid || dataset_binding.as_bytes() == &[0; 32]
        || physical_row_digest.as_bytes() == &[0; 32] {
        return Err(ZfsWorkerError::Authority);
    }
    let catalog = crate::CatalogBindingV1::from_publisher(generation, head)
        .map_err(|_| ZfsWorkerError::Authority)?;
    Ok(CaptureWorkerCatalogDataV3 { catalog, guid, dataset_binding, physical_row_digest,
        source: context.source_v3().source_digest_v2(), request: context.request_digest_v3() })
}


const MOUNTED_MAGIC: &[u8; 8] = b"AOSCWM03";
pub(in crate::process) const MOUNTED_BYTES_V3: usize = 306;

pub(in crate::process) struct CaptureMountedReportDataV3 {
    pub(in crate::process) dataset_binding: ObjectDigest,
    pub(in crate::process) mount_id: u64,
    pub(in crate::process) before: ObjectDigest,
    pub(in crate::process) mounted: ObjectDigest,
    pub(in crate::process) pipe_identities: [(u64, u64); 2],
}

pub(super) fn encode_mounted_v3(
    context: &AuthenticatedCaptureWorkerContextV3<'_>,
    catalog: &super::CaptureWorkerCatalogOriginalV3,
    writer: &crate::execution_capture_zfs_worker::PreparedDetachedCaptureWriterV1,
    identities: [(u64, u64); 2],
) -> Result<[u8; MOUNTED_BYTES_V3], ZfsWorkerError> {
    let catalog = catalog.require_context_v3(context).ok_or(ZfsWorkerError::Authority)?;
    let mounted = writer.mounted_data_v3(context).map_err(|_| worker_entry::retained())?;
    if mounted.dataset_binding != catalog.dataset_binding || mounted.mount_id == 0
        || identities[0] == identities[1] || identities.iter().any(|(_, inode)| *inode == 0)
    { return Err(ZfsWorkerError::Authority); }
    let mut bytes = [0; MOUNTED_BYTES_V3];
    bytes[..8].copy_from_slice(MOUNTED_MAGIC);
    bytes[8..10].copy_from_slice(&VERSION.to_be_bytes());
    let mut offset = 10;
    for field in [context.request_digest_v3(), mounted.source, mounted.durable,
        mounted.dataset_binding, catalog.physical_row_digest]
    {
        bytes[offset..offset + 32].copy_from_slice(field.as_bytes());
        offset += 32;
    }
    bytes[170..178].copy_from_slice(&mounted.mount_id.to_be_bytes());
    bytes[178..210].copy_from_slice(mounted.before.as_bytes());
    bytes[210..242].copy_from_slice(mounted.mounted.as_bytes());
    for (index, (device, inode)) in identities.into_iter().enumerate() {
        let start = 242 + index * 16;
        bytes[start..start + 8].copy_from_slice(&device.to_be_bytes());
        bytes[start + 8..start + 16].copy_from_slice(&inode.to_be_bytes());
    }
    let check = digest(&bytes[..274]);
    bytes[274..].copy_from_slice(check.as_bytes());
    Ok(bytes)
}

pub(in crate::process) fn decode_mounted_v3(
    bytes: &[u8],
    request: &[u8],
    native: &crate::execution_capture_zfs_worker::NativeCaptureCreateOriginalV3,
    catalog: &crate::state::CaptureStateCatalogOriginalV3,
    physical: &crate::execution_output::CapturePhysicalBindingOriginalV3,
) -> Result<CaptureMountedReportDataV3, ZfsWorkerError> {
    if bytes.len() != MOUNTED_BYTES_V3 || request.len() < 32
        || digest(&bytes[..274]).as_bytes() != &bytes[274..]
    { return Err(ZfsWorkerError::Authority); }
    let dataset = catalog.dataset_for_native_v3(native).ok_or(ZfsWorkerError::Authority)?;
    let physical = physical.row_digest_for_native_v3(native).ok_or(ZfsWorkerError::Authority)?;
    let mut decoder = Decoder::new(&bytes[..274]);
    if decoder.take(8)? != MOUNTED_MAGIC || decoder.u16()? != VERSION
        || decoder.take(32)? != &request[request.len() - 32..]
        || decoder.take(32)? != native.admission_v3().source_v3().source_digest_v2().as_bytes()
        || decoder.take(32)? != native.durable_attempt_digest_v3().as_bytes()
        || decoder.take(32)? != dataset.binding().as_bytes()
        || decoder.take(32)? != physical.as_bytes()
    { return Err(ZfsWorkerError::Authority); }
    let mount_id = decoder.u64()?;
    let before = ObjectDigest::from_bytes(decoder.array()?);
    let mounted = ObjectDigest::from_bytes(decoder.array()?);
    let pipe_identities = [(decoder.u64()?, decoder.u64()?), (decoder.u64()?, decoder.u64()?)];
    decoder.finish()?;
    if mount_id == 0 || before.as_bytes() == &[0; 32] || mounted.as_bytes() == &[0; 32]
        || pipe_identities[0] == pipe_identities[1]
        || pipe_identities.iter().any(|(_, inode)| *inode == 0)
    { return Err(ZfsWorkerError::Authority); }
    Ok(CaptureMountedReportDataV3 { dataset_binding: dataset.binding(), mount_id, before, mounted, pipe_identities })
}


const COMPLETED_MAGIC: &[u8; 8] = b"AOSCWZ03";
pub(in crate::process) const COMPLETED_BYTES_V3: usize = 487;

pub(super) fn encode_completed_v3(
    context: &AuthenticatedCaptureWorkerContextV3<'_>,
    completed: &crate::execution_capture_zfs_worker::CaptureWriterCompletionOriginalV3,
) -> Result<[u8; COMPLETED_BYTES_V3], ZfsWorkerError> {
    let result = completed.result_v3().ok_or(ZfsWorkerError::Authority)?;
    let (_, _, _, _, durable, _, _) = crate::execution_output::capture_worker_inputs_v3(context)
        .map_err(|_| ZfsWorkerError::Authority)?;
    let mut bytes = [0; COMPLETED_BYTES_V3];
    bytes[..8].copy_from_slice(COMPLETED_MAGIC);
    bytes[8..10].copy_from_slice(&VERSION.to_be_bytes());
    for (index, field) in [context.request_digest_v3(), context.source_v3().source_digest_v2(), durable]
        .into_iter().enumerate()
    { let start = 10 + index * 32; bytes[start..start + 32].copy_from_slice(field.as_bytes()); }
    bytes[106..122].copy_from_slice(&result.attempt);
    bytes[122..154].copy_from_slice(result.record_digest.as_bytes());
    bytes[154..186].copy_from_slice(result.dataset_binding.as_bytes());
    bytes[186..194].copy_from_slice(&result.mount_id.to_be_bytes());
    for (index, field) in [result.before_observation_digest, result.mounted_observation_digest,
        result.after_observation_digest].into_iter().enumerate()
    { let start = 194 + index * 32; bytes[start..start + 32].copy_from_slice(field.as_bytes()); }
    for (index, stream) in [&result.written.stdout, &result.written.stderr].into_iter().enumerate() {
        let start = 290 + index * 49;
        bytes[start..start + 8].copy_from_slice(&stream.maximum_bytes.to_be_bytes());
        bytes[start + 8..start + 16].copy_from_slice(&stream.captured_bytes.to_be_bytes());
        bytes[start + 16] = u8::from(stream.truncated);
        bytes[start + 17..start + 49].copy_from_slice(stream.content_digest.as_bytes());
    }
    bytes[388..391].copy_from_slice(&[u8::from(result.written.stdout_eof),
        u8::from(result.written.stderr_eof), u8::from(result.written.synced_readback)]);
    bytes[391..423].copy_from_slice(result.written.result_digest.as_bytes());
    bytes[423..455].copy_from_slice(result.result_digest.as_bytes());
    let check = digest(&bytes[..455]);
    bytes[455..].copy_from_slice(check.as_bytes());
    Ok(bytes)
}

// Parsed fields remain DATA until the real parent additionally joins this
// actual received record's READY subject, current cgroup and owed source posts.
pub(in crate::process) fn decode_completed_v3(
    bytes: &[u8], request: &[u8], native: &crate::execution_capture_zfs_worker::NativeCaptureCreateOriginalV3,
    mounted: &CaptureMountedReportDataV3,
) -> Result<crate::execution_capture_zfs_worker::UnboundCaptureWorkerResultV1, ZfsWorkerError> {
    use crate::execution_capture_writer::{UnboundCapturedStreamV1, UnboundCaptureWriteResultV1,
        capture_write_result_digest_v3};
    use crate::execution_capture_zfs_worker::UnboundCaptureWorkerResultV1;
    if bytes.len() != COMPLETED_BYTES_V3 || request.len() < 32
        || digest(&bytes[..455]).as_bytes() != &bytes[455..]
    { return Err(ZfsWorkerError::Authority); }
    let original = native.admission_v3().source_v3().original_source_v1();
    let identity = native.worker_result_identity_v3();
    let mut decoder = Decoder::new(&bytes[..455]);
    if decoder.take(8)? != COMPLETED_MAGIC || decoder.u16()? != VERSION
        || decoder.take(32)? != &request[request.len() - 32..]
        || decoder.take(32)? != native.admission_v3().source_v3().source_digest_v2().as_bytes()
        || decoder.take(32)? != identity.durable.as_bytes()
        || decoder.take(16)? != identity.attempt
    { return Err(ZfsWorkerError::Authority); }
    let record_digest = ObjectDigest::from_bytes(decoder.array()?);
    let dataset_binding = ObjectDigest::from_bytes(decoder.array()?);
    let mount_id = decoder.u64()?;
    let before = ObjectDigest::from_bytes(decoder.array()?);
    let mounted_digest = ObjectDigest::from_bytes(decoder.array()?);
    let after = ObjectDigest::from_bytes(decoder.array()?);
    fn stream(decoder: &mut Decoder<'_>) -> Result<UnboundCapturedStreamV1, ZfsWorkerError> {
        let maximum_bytes = decoder.u64()?;
        let captured_bytes = decoder.u64()?;
        let truncated = match decoder.take(1)? { [0] => false, [1] => true,
            _ => return Err(ZfsWorkerError::Authority) };
        let content_digest = ObjectDigest::from_bytes(decoder.array()?);
        if captured_bytes > maximum_bytes || truncated && captured_bytes != maximum_bytes
            || content_digest.as_bytes() == &[0; 32]
            || captured_bytes == 0 && content_digest.as_bytes() != Sha256::digest([]).as_slice()
        { return Err(ZfsWorkerError::Authority); }
        Ok(UnboundCapturedStreamV1 { maximum_bytes, captured_bytes, truncated, content_digest })
    }
    let stdout = stream(&mut decoder)?;
    let stderr = stream(&mut decoder)?;
    if decoder.take(3)? != [1, 1, 1] { return Err(ZfsWorkerError::Authority); }
    let written_digest = ObjectDigest::from_bytes(decoder.array()?);
    let result_digest = ObjectDigest::from_bytes(decoder.array()?);
    decoder.finish()?;
    let (_, stdout_limit, stderr_limit) = original.output_limits();
    if record_digest != original.output_record_digest() || dataset_binding != mounted.dataset_binding
        || mount_id != mounted.mount_id
        || before != mounted.before || mounted_digest != mounted.mounted
        || after.as_bytes() == &[0; 32] || stdout.maximum_bytes != stdout_limit || stderr.maximum_bytes != stderr_limit
        || written_digest != capture_write_result_digest_v3(record_digest, &stdout, &stderr)
    { return Err(ZfsWorkerError::Authority); }
    let result = UnboundCaptureWorkerResultV1 { attempt: identity.attempt, record_digest, dataset_binding, mount_id,
        before_observation_digest: before, mounted_observation_digest: mounted_digest,
        after_observation_digest: after,
        written: UnboundCaptureWriteResultV1 { record_digest, stdout, stderr,
            stdout_eof: true, stderr_eof: true, synced_readback: true, result_digest: written_digest }, result_digest };
    if result.result_digest_data_v3(&identity) != result_digest { return Err(ZfsWorkerError::Authority); }
    Ok(result)
}


pub(in crate::process) const FINAL_ACK_BYTES_V3: usize = 106;

// This private unshipped ACK acknowledges the exact authenticated report.
// It is sent before waiting for worker death and publishing676; it attests no
// durable Output record, Host terminal completion or financial disposal.
pub(in crate::process) fn final_ack_data_v3(
    request: ObjectDigest, source: ObjectDigest, completed: &[u8],
) -> Result<[u8; FINAL_ACK_BYTES_V3], ZfsWorkerError> {
    if completed.len() != COMPLETED_BYTES_V3
        || digest(&completed[..455]).as_bytes() != &completed[455..]
    { return Err(ZfsWorkerError::Authority); }
    let mut bytes = [0; FINAL_ACK_BYTES_V3];
    bytes[..8].copy_from_slice(b"AOSCWF03");
    bytes[8..10].copy_from_slice(&VERSION.to_be_bytes());
    bytes[10..42].copy_from_slice(request.as_bytes());
    bytes[42..74].copy_from_slice(source.as_bytes());
    bytes[74..106].copy_from_slice(&completed[455..]);
    Ok(bytes)
}


#[cfg(test)]
mod final_report_ack_tests {
    use super::*;

    #[test]
    fn acknowledgement_binds_report_bytes_without_promising_a_future_commit() {
        // This is deliberately DATA, not a Native report/admission constructor.
        // The real parent first validates the whole authenticated487 report.
        let request = ObjectDigest::from_bytes([1; 32]);
        let source = ObjectDigest::from_bytes([2; 32]);
        let mut report = [0_u8; COMPLETED_BYTES_V3];
        report[..8].copy_from_slice(COMPLETED_MAGIC);
        report[8..10].copy_from_slice(&VERSION.to_be_bytes());
        let checksum = digest(&report[..455]);
        report[455..].copy_from_slice(checksum.as_bytes());

        let ack = final_ack_data_v3(request, source, &report).unwrap();
        assert_eq!(ack.len(), 106);
        assert_eq!(&ack[10..42], request.as_bytes());
        assert_eq!(&ack[42..74], source.as_bytes());
        assert_eq!(&ack[74..], checksum.as_bytes());

        report[100] ^= 1;
        assert!(final_ack_data_v3(request, source, &report).is_err());
        let changed_checksum = digest(&report[..455]);
        report[455..].copy_from_slice(changed_checksum.as_bytes());
        assert_ne!(final_ack_data_v3(request, source, &report).unwrap(), ack);
    }
}
