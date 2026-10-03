//! Exact, nonauthorizing held-snapshot observation in the fixed ZFS worker.
//!
//! ```text
//! AOSZHS01 request = version | executable | managed root | source dataset |
//!   snapshot | hold ID | expected pool GUID | catalog head | authority head |
//!   fresh nonce
//! AOSZHO01 response = version | request digest | state | pool GUID |
//!   physical observation digest
//! ```
//!
//! A response proves only what the authenticated one-shot worker observed.
//! The protected caller must select the snapshot under its catalog lock and
//! recheck the same catalog and authority heads after worker quiescence.

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStringExt as _;
use std::path::PathBuf;

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_linux::process::{FixedProcessOutcome, FixedProcessRequest, run_fixed_process};
use aos_sandbox_protocol::semantics::CatalogBindingV1;
use sha2::{Digest as _, Sha256};

use crate::observation::{ZfsObservationPlan, ZfsObservationState};
use crate::{
    HoldId, ManagedDatasetRoot, ResolvedDataset, ResolvedSnapshot, StorageDomainsV1,
    ZfsHelperContract,
};

use super::{
    CaptureZfsToolV1, Deadline, Decoder, PinnedCaptureZfsTools, ZfsWorkerError, execute_observation,
};
use super::original_cutoff::{
    OriginalBoottimeTimerV3, OriginalCutoffExchangeV3, OriginalWorkerCutoffErrorV3,
    WorkerOriginalCheckedViewV3,
};
use crate::runtime::original_held_measurement::OriginalHeldMeasurementErrorV3;

const REQUEST_MAGIC: &[u8; 8] = b"AOSZHS01";
const RESPONSE_MAGIC: &[u8; 8] = b"AOSZHO01";
const VERSION: u16 = 1;
const REQUEST_DOMAIN: &[u8] = b"aos.sandbox.storage.held-snapshot-worker-request.v1\0";
const PHYSICAL_DOMAIN: &[u8] = b"aos.sandbox.storage.held-snapshot-physical.v1\0";
const MAXIMUM_REQUEST_BYTES: usize = 6 * 1024;
const MAXIMUM_POOL_OUTPUT_BYTES: usize = 512;
pub(super) const RESPONSE_BYTES: usize = 83;

/// Binds a worker sample to one current protected cut and fresh dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HeldSnapshotWorkerBindingV1 {
    /// The exact physical pool GUID expected by the protected caller.
    pub(crate) pool_guid: u64,
    /// The freshly recovered physical-catalog head.
    pub(crate) catalog: CatalogBindingV1,
    /// The protected Storage journal sequence before worker dispatch.
    pub(crate) authority_sequence: u64,
    /// A fresh dispatch identity that prevents accepting a prior response.
    pub(crate) nonce: [u8; 16],
}

pub(super) struct HeldSnapshotWorkerRequestV1 {
    pub(super) executable: ZfsHelperContract,
    pub(super) snapshot: ResolvedSnapshot,
    pub(super) hold_id: HoldId,
    pub(super) binding: HeldSnapshotWorkerBindingV1,
    pub(super) digest: ObjectDigest,
}

/// Carries only a physical sample; it is neither a signed hold receipt nor a SourceRoot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HeldSnapshotPhysicalObservationV1 {
    Matched {
        pool_guid: u64,
        digest: ObjectDigest,
    },
    Mismatch,
}

pub(super) fn is_request(bytes: &[u8]) -> bool {
    bytes.starts_with(REQUEST_MAGIC)
}

pub(super) fn encode_request(
    executable: &ZfsHelperContract,
    snapshot: &ResolvedSnapshot,
    hold_id: HoldId,
    binding: HeldSnapshotWorkerBindingV1,
) -> Result<Vec<u8>, ZfsWorkerError> {
    if binding.pool_guid == 0 || binding.authority_sequence == 0 || binding.nonce == [0; 16] {
        return Err(ZfsWorkerError::Protocol(
            "held-snapshot request identity is invalid",
        ));
    }

    let dataset = snapshot.dataset();
    let root = dataset.root();
    let domains = dataset.domains();
    let mut bytes = Vec::with_capacity(512);
    bytes.extend_from_slice(REQUEST_MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    encode_text(&mut bytes, executable.executable().as_os_str())?;
    encode_text(&mut bytes, OsStr::new(root.pool()))?;
    encode_text(&mut bytes, OsStr::new(root.dataset_prefix()))?;
    bytes.extend_from_slice(&root.guid().to_be_bytes());
    encode_text(&mut bytes, OsStr::new(dataset.name()))?;
    bytes.extend_from_slice(&dataset.guid().to_be_bytes());
    bytes.extend_from_slice(&dataset.storage_handle());
    for domain in [
        domains.disclosure(),
        domains.encryption(),
        domains.accounting(),
        domains.retention(),
    ] {
        bytes.extend_from_slice(domain.as_bytes());
    }
    encode_text(&mut bytes, OsStr::new(snapshot.component()))?;
    bytes.extend_from_slice(&snapshot.guid().to_be_bytes());
    bytes.extend_from_slice(&snapshot.version_handle());
    bytes.extend_from_slice(&hold_id.as_bytes());
    bytes.extend_from_slice(&binding.pool_guid.to_be_bytes());
    bytes.extend_from_slice(&binding.catalog.generation().to_be_bytes());
    bytes.extend_from_slice(binding.catalog.digest().as_bytes());
    bytes.extend_from_slice(&binding.authority_sequence.to_be_bytes());
    bytes.extend_from_slice(&binding.nonce);
    if bytes.len() > MAXIMUM_REQUEST_BYTES {
        return Err(ZfsWorkerError::Protocol(
            "held-snapshot request exceeds ceiling",
        ));
    }
    Ok(bytes)
}

pub(super) fn decode_request(bytes: &[u8]) -> Result<HeldSnapshotWorkerRequestV1, ZfsWorkerError> {
    if bytes.len() > MAXIMUM_REQUEST_BYTES {
        return Err(ZfsWorkerError::Protocol(
            "held-snapshot request exceeds ceiling",
        ));
    }
    let mut decoder = Decoder::new(bytes);
    if decoder.take(8)? != REQUEST_MAGIC || decoder.u16()? != VERSION {
        return Err(ZfsWorkerError::Protocol(
            "held-snapshot request version mismatch",
        ));
    }
    let executable = ZfsHelperContract::new(PathBuf::from(OsString::from_vec(
        decode_text(&mut decoder)?.into_bytes(),
    )))?;
    let pool = decode_text(&mut decoder)?;
    let prefix = decode_text(&mut decoder)?;
    let root = ManagedDatasetRoot::from_catalog(&pool, &prefix, decoder.u64()?)
        .map_err(|_| ZfsWorkerError::Protocol("held-snapshot root is invalid"))?;
    let source_name = decode_text(&mut decoder)?;
    let source_guid = decoder.u64()?;
    let storage_handle = decoder.array()?;
    let domains = StorageDomainsV1::new(
        ObjectDigest::from_bytes(decoder.array()?),
        ObjectDigest::from_bytes(decoder.array()?),
        ObjectDigest::from_bytes(decoder.array()?),
        ObjectDigest::from_bytes(decoder.array()?),
    )
    .map_err(|_| ZfsWorkerError::Protocol("held-snapshot domains are invalid"))?;
    let dataset =
        ResolvedDataset::from_catalog(root, &source_name, source_guid, storage_handle, domains)
            .map_err(|_| ZfsWorkerError::Protocol("held-snapshot source is invalid"))?;
    let component = decode_text(&mut decoder)?;
    let snapshot =
        ResolvedSnapshot::from_catalog(dataset, &component, decoder.u64()?, decoder.array()?)
            .map_err(|_| ZfsWorkerError::Protocol("held-snapshot identity is invalid"))?;
    let hold_id = HoldId::from_bytes(decoder.array()?)
        .map_err(|_| ZfsWorkerError::Protocol("held-snapshot hold is invalid"))?;
    let pool_guid = decoder.u64()?;
    let catalog = CatalogBindingV1::from_publisher(
        decoder.u64()?,
        ObjectDigest::from_bytes(decoder.array()?),
    )
    .map_err(|_| ZfsWorkerError::Protocol("held-snapshot catalog is invalid"))?;
    let authority_sequence = decoder.u64()?;
    let nonce = decoder.array()?;
    decoder.finish()?;
    if pool_guid == 0 || authority_sequence == 0 || nonce == [0; 16] {
        return Err(ZfsWorkerError::Protocol(
            "held-snapshot request identity is invalid",
        ));
    }

    let binding = HeldSnapshotWorkerBindingV1 {
        pool_guid,
        catalog,
        authority_sequence,
        nonce,
    };
    if encode_request(&executable, &snapshot, hold_id, binding)? != bytes {
        return Err(ZfsWorkerError::Protocol(
            "held-snapshot request is noncanonical",
        ));
    }

    Ok(HeldSnapshotWorkerRequestV1 {
        executable,
        snapshot,
        hold_id,
        binding,
        digest: request_digest(bytes),
    })
}

pub(super) fn request_digest(bytes: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(REQUEST_DOMAIN)
            .chain_update(bytes)
            .finalize()
            .into(),
    )
}

pub(super) fn encode_response(
    request_digest: ObjectDigest,
    observation: HeldSnapshotPhysicalObservationV1,
) -> [u8; RESPONSE_BYTES] {
    encode_response_for(request_digest, observation, RESPONSE_MAGIC, VERSION)
}

pub(super) fn encode_original_response(
    request_digest: ObjectDigest,
    observation: HeldSnapshotPhysicalObservationV1,
) -> [u8; RESPONSE_BYTES] {
    encode_response_for(request_digest, observation, b"AOSZHO02", 2)
}

fn encode_response_for(
    request_digest: ObjectDigest,
    observation: HeldSnapshotPhysicalObservationV1,
    magic: &[u8; 8],
    version: u16,
) -> [u8; RESPONSE_BYTES] {
    let mut bytes = [0_u8; RESPONSE_BYTES];
    bytes[..8].copy_from_slice(magic);
    bytes[8..10].copy_from_slice(&version.to_be_bytes());
    bytes[10..42].copy_from_slice(request_digest.as_bytes());
    match observation {
        HeldSnapshotPhysicalObservationV1::Matched { pool_guid, digest } => {
            bytes[42] = 1;
            bytes[43..51].copy_from_slice(&pool_guid.to_be_bytes());
            bytes[51..83].copy_from_slice(digest.as_bytes());
        }
        HeldSnapshotPhysicalObservationV1::Mismatch => bytes[42] = 2,
    }
    bytes
}

pub(super) fn decode_response(
    bytes: &[u8],
    expected_request_digest: ObjectDigest,
) -> Result<HeldSnapshotPhysicalObservationV1, ZfsWorkerError> {
    decode_response_for(bytes, expected_request_digest, RESPONSE_MAGIC, VERSION)
}

pub(super) fn decode_original_response(
    bytes: &[u8],
    expected_request_digest: ObjectDigest,
) -> Result<HeldSnapshotPhysicalObservationV1, ZfsWorkerError> {
    decode_response_for(bytes, expected_request_digest, b"AOSZHO02", 2)
}

fn decode_response_for(
    bytes: &[u8],
    expected_request_digest: ObjectDigest,
    magic: &[u8; 8],
    version: u16,
) -> Result<HeldSnapshotPhysicalObservationV1, ZfsWorkerError> {
    if bytes.len() != RESPONSE_BYTES {
        return Err(ZfsWorkerError::Protocol(
            "held-snapshot response length is invalid",
        ));
    }
    let mut decoder = Decoder::new(bytes);
    if decoder.take(8)? != magic || decoder.u16()? != version {
        return Err(ZfsWorkerError::Protocol(
            "held-snapshot response version mismatch",
        ));
    }
    if decoder.array::<32>()? != *expected_request_digest.as_bytes() {
        return Err(ZfsWorkerError::Protocol(
            "held-snapshot response request changed",
        ));
    }
    let state = decoder.byte()?;
    let pool_guid = decoder.u64()?;
    let digest = ObjectDigest::from_bytes(decoder.array()?);
    decoder.finish()?;
    match state {
        1 if pool_guid != 0 && digest.as_bytes() != &[0; 32] => {
            Ok(HeldSnapshotPhysicalObservationV1::Matched { pool_guid, digest })
        }
        2 if pool_guid == 0 && digest.as_bytes() == &[0; 32] => {
            Ok(HeldSnapshotPhysicalObservationV1::Mismatch)
        }
        _ => Err(ZfsWorkerError::Protocol(
            "held-snapshot response state is invalid",
        )),
    }
}

pub(super) fn validate_original_selected(
    cutoff: &super::original_cutoff::DecodedOriginalWorkerCutoffV3,
    selected: &[u8],
) -> Result<HeldSnapshotWorkerRequestV1, ZfsWorkerError> {
    let request = decode_request(selected)?;
    let claims = cutoff.request.request().claims();
    let catalog = claims.catalog();
    let (_, snapshot) = catalog.select_under_head(
        catalog.generation(), catalog.digest(), catalog.namespace_digest(), claims.selection().0,
    ).map_err(|_| ZfsWorkerError::Authority)?;
    if request.snapshot.dataset().storage_handle() != snapshot.storage_handle()
        || request.snapshot.dataset().guid() != snapshot.dataset_guid()
        || request.snapshot.guid() != snapshot.snapshot_guid()
        || request.hold_id.as_bytes() != snapshot.hold_id()
        || request.binding.pool_guid != snapshot.pool_guid()
    {
        return Err(ZfsWorkerError::Authority);
    }
    Ok(request)
}

pub(super) fn execute_request(
    request: &HeldSnapshotWorkerRequestV1,
    deadline: Deadline,
) -> Result<HeldSnapshotPhysicalObservationV1, ZfsWorkerError> {
    let tools = PinnedCaptureZfsTools::new(
        &request.executable,
        "held-snapshot worker requires fixed zfs executable",
    )?;
    let first_pool = observe_pool_guid(&tools, request.snapshot.dataset().root().pool(), deadline)?;
    if first_pool.0 != request.binding.pool_guid {
        return Ok(HeldSnapshotPhysicalObservationV1::Mismatch);
    }

    let plan = ZfsObservationPlan::held_snapshot(&request.snapshot, request.hold_id)
        .map_err(|_| ZfsWorkerError::Protocol("held-snapshot plan is invalid"))?;
    let observation = execute_observation(&request.executable, &plan, deadline)?;
    if observation.state != ZfsObservationState::Matched {
        return Ok(HeldSnapshotPhysicalObservationV1::Mismatch);
    }
    let observed_digest = observation
        .digest
        .ok_or(ZfsWorkerError::Protocol("held-snapshot digest is missing"))?;
    let second_pool =
        observe_pool_guid(&tools, request.snapshot.dataset().root().pool(), deadline)?;
    tools.validate_current()?;
    if second_pool.0 != first_pool.0 {
        return Ok(HeldSnapshotPhysicalObservationV1::Mismatch);
    }

    let digest = ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(PHYSICAL_DOMAIN)
            .chain_update(request.digest.as_bytes())
            .chain_update(&first_pool.1)
            .chain_update(observed_digest.as_bytes())
            .chain_update(&second_pool.1)
            .finalize()
            .into(),
    );
    Ok(HeldSnapshotPhysicalObservationV1::Matched {
        pool_guid: first_pool.0,
        digest,
    })
}

/// Retains the actual tools, timers, output and lower diagnostics for seven probes.
pub(super) struct OriginalProbeProgressV3 {
    zfs_pin: Option<super::PinnedExecutable>,
    zpool_pin: Option<super::PinnedExecutable>,
    zpool: Option<ZfsHelperContract>,
    captures: [aos_sandbox_linux::process::FixedProcessCaptureV1; 7],
    outcomes: [Option<aos_sandbox_linux::process::FixedProcessRetainedSessionOutcome<()>>; 7],
    timers: [OriginalBoottimeTimerV3; 7],
    post_image_checks: [Option<Result<(), ZfsWorkerError>>; 7],
    next: usize,
}

impl Default for OriginalProbeProgressV3 {
    fn default() -> Self {
        Self {
            zfs_pin: None,
            zpool_pin: None,
            zpool: None,
            captures: std::array::from_fn(|_| aos_sandbox_linux::process::FixedProcessCaptureV1::new()),
            outcomes: std::array::from_fn(|_| None),
            timers: std::array::from_fn(|_| OriginalBoottimeTimerV3::default()),
            post_image_checks: std::array::from_fn(|_| None),
            next: 0,
        }
    }
}

pub(super) fn execute_original_request(
    request: &HeldSnapshotWorkerRequestV1,
    view: &mut WorkerOriginalCheckedViewV3<'_>,
    progress: &mut OriginalProbeProgressV3,
) -> Result<HeldSnapshotPhysicalObservationV1, OriginalHeldMeasurementErrorV3> {
    view.check()?;
    if request
        .executable
        .executable()
        .file_name()
        .is_none_or(|name| name != "zfs")
    {
        return Err(ZfsWorkerError::Executable(
            "held-snapshot worker requires fixed zfs executable".to_owned(),
        )
        .into());
    }
    progress.zpool = Some(
        ZfsHelperContract::new(request.executable.executable().with_file_name("zpool"))
            .map_err(ZfsWorkerError::from)?,
    );
    super::PinnedExecutable::capture_open(&request.executable, &mut progress.zfs_pin)?;
    super::PinnedExecutable::capture_open(
        progress
            .zpool
            .as_ref()
            .ok_or(OriginalHeldMeasurementErrorV3::Closed)?,
        &mut progress.zpool_pin,
    )?;
    view.check()?;

    let pool = request.snapshot.dataset().root().pool();
    let pool_arguments = ["list", "-H", "-p", "-o", "name,guid", pool].map(OsString::from);
    let first_pool = run_original_command(
        request,
        view,
        progress,
        CaptureZfsToolV1::Zpool,
        &pool_arguments,
        MAXIMUM_POOL_OUTPUT_BYTES,
        0,
    )?;
    let first_guid = parse_pool_guid(progress.captures[first_pool].stdout(), pool)?;
    if first_guid != request.binding.pool_guid {
        return Ok(HeldSnapshotPhysicalObservationV1::Mismatch);
    }
    let plan = ZfsObservationPlan::held_snapshot(&request.snapshot, request.hold_id)
        .map_err(|_| ZfsWorkerError::Protocol("held-snapshot plan is invalid"))?;
    if plan.commands().len() != 5 {
        return Err(OriginalHeldMeasurementErrorV3::Bound);
    }
    let mut evaluation = plan.evaluation();
    let mut output_bytes = 0_usize;
    let mut observed = None;
    for command in plan.commands() {
        view.check()?;
        let index = run_original_command(
            request,
            view,
            progress,
            CaptureZfsToolV1::Zfs,
            command.arguments(),
            super::MAXIMUM_STDOUT_BYTES.saturating_sub(output_bytes),
            super::MAXIMUM_STDERR_BYTES,
        )?;
        let captured = progress.captures[index].stdout();
        output_bytes = output_bytes
            .checked_add(captured.len())
            .filter(|bytes| *bytes <= super::MAXIMUM_STDOUT_BYTES)
            .ok_or(OriginalHeldMeasurementErrorV3::Bound)?;
        // The existing evaluator owns its input Vec. Keep the lower capture
        // separately so errors never discard the original stdout/stderr.
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(captured.len())?;
        bytes.extend_from_slice(captured);
        observed = evaluation
            .accept(bytes)
            .map_err(|_| ZfsWorkerError::Protocol("invalid ZFS observation output"))?;
        view.check()?;
        if observed.is_some() {
            break;
        }
    }
    let observation = observed.ok_or(ZfsWorkerError::Protocol(
        "ZFS observation plan did not produce a result",
    ))?;
    if observation.state != ZfsObservationState::Matched {
        return Ok(HeldSnapshotPhysicalObservationV1::Mismatch);
    }
    let observed_digest = observation.digest.ok_or(ZfsWorkerError::Protocol(
        "held-snapshot digest is missing",
    ))?;
    let second_pool = run_original_command(
        request,
        view,
        progress,
        CaptureZfsToolV1::Zpool,
        &pool_arguments,
        MAXIMUM_POOL_OUTPUT_BYTES,
        0,
    )?;
    let second_guid = parse_pool_guid(progress.captures[second_pool].stdout(), pool)?;
    view.check()?;
    if second_guid != first_guid {
        return Ok(HeldSnapshotPhysicalObservationV1::Mismatch);
    }
    let digest = ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(PHYSICAL_DOMAIN)
            .chain_update(view.digest().as_bytes())
            .chain_update(progress.captures[first_pool].stdout())
            .chain_update(observed_digest.as_bytes())
            .chain_update(progress.captures[second_pool].stdout())
            .finalize()
            .into(),
    );
    Ok(HeldSnapshotPhysicalObservationV1::Matched {
        pool_guid: first_guid,
        digest,
    })
}

fn run_original_command(
    request: &HeldSnapshotWorkerRequestV1,
    view: &mut WorkerOriginalCheckedViewV3<'_>,
    progress: &mut OriginalProbeProgressV3,
    tool: CaptureZfsToolV1,
    arguments: &[OsString],
    maximum_stdout_bytes: usize,
    maximum_stderr_bytes: usize,
) -> Result<usize, OriginalHeldMeasurementErrorV3> {
    use aos_sandbox_linux::process::{
        FixedProcessCapturedStreamV1, FixedProcessRetainedSessionOutcome,
        FixedProcessSessionRequest, run_fixed_process_session_retained_v1,
    };

    let index = progress.next;
    if index >= progress.captures.len()
        || maximum_stdout_bytes > super::MAXIMUM_STDOUT_BYTES
        || maximum_stderr_bytes > super::MAXIMUM_STDERR_BYTES
    {
        return Err(OriginalHeldMeasurementErrorV3::Bound);
    }
    progress.next += 1;
    let (contract, pin) = match tool {
        CaptureZfsToolV1::Zfs => (&request.executable, progress.zfs_pin.as_ref()),
        CaptureZfsToolV1::Zpool => (
            progress
                .zpool
                .as_ref()
                .ok_or(OriginalHeldMeasurementErrorV3::Closed)?,
            progress.zpool_pin.as_ref(),
        ),
    };
    let pin = pin.ok_or(OriginalHeldMeasurementErrorV3::Closed)?;
    pin.validate_current(contract)?;
    let later = view.check()?;
    let remaining = view
        .cutoff()
        .checked_sub(later.boottime_nanoseconds())
        .filter(|remaining| *remaining != 0)
        .ok_or(OriginalHeldMeasurementErrorV3::Closed)?;
    progress.timers[index].arm(view.cutoff())?;
    let result = {
        let mut exchange = OriginalCutoffExchangeV3::new(view);
        run_fixed_process_session_retained_v1(
            FixedProcessSessionRequest {
                process: FixedProcessRequest {
                    executable: contract.executable(),
                    arguments,
                    timeout: std::time::Duration::from_nanos(remaining),
                    maximum_stdout_bytes,
                    maximum_stderr_bytes,
                },
                stdin: None,
                inherited: Vec::new(),
                control: progress.timers[index].descriptor()?,
            },
            &mut exchange,
            &mut progress.captures[index],
        )
    };
    progress.post_image_checks[index] = Some(pin.validate_current(contract));
    let post_clock = view.check();
    // The runner's first concrete cause precedes the later bookend checks.
    let outcome = result?;
    progress.outcomes[index] = Some(outcome);
    if matches!(&progress.post_image_checks[index], Some(Err(_))) {
        if let Some(Err(cause)) = progress.post_image_checks[index].take() {
            return Err(cause.into());
        }
    }
    if let Err(cause) = post_clock {
        return Err(view.take_first_failure().unwrap_or(cause).into());
    }
    let success = matches!(
        &progress.outcomes[index],
        Some(FixedProcessRetainedSessionOutcome::ChildExitedBeforeExchange {
            exit_code: Some(0),
            signal: None,
        }),
    );
    let capture = &progress.captures[index];
    if !success
        || !capture.stderr().is_empty()
        || capture.observation().stdout() != FixedProcessCapturedStreamV1::Eof
        || capture.observation().stderr() != FixedProcessCapturedStreamV1::Eof
        || !capture.observation().reaped() || capture.observation().ownership_lost()
    {
        return Err(ZfsWorkerError::Protocol(
            "held-snapshot original command did not complete",
        )
        .into());
    }
    Ok(index)
}

fn observe_pool_guid(
    tools: &PinnedCaptureZfsTools<'_>,
    pool: &str,
    deadline: Deadline,
) -> Result<(u64, Vec<u8>), ZfsWorkerError> {
    let (contract, pin) = tools.for_tool(CaptureZfsToolV1::Zpool);
    pin.validate_current(contract)?;
    let timeout = deadline.remaining().ok_or(ZfsWorkerError::Protocol(
        "held-snapshot pool readback timed out",
    ))?;
    let arguments = ["list", "-H", "-p", "-o", "name,guid", pool].map(OsString::from);
    let outcome = run_fixed_process(FixedProcessRequest {
        executable: contract.executable(),
        arguments: &arguments,
        timeout,
        maximum_stdout_bytes: MAXIMUM_POOL_OUTPUT_BYTES,
        maximum_stderr_bytes: 0,
    })?;
    let output = match outcome {
        FixedProcessOutcome::Completed(output)
            if output.exit_code == Some(0)
                && output.signal.is_none()
                && output.stderr.is_empty() =>
        {
            output.stdout
        }
        _ => {
            return Err(ZfsWorkerError::Protocol(
                "held-snapshot pool readback failed",
            ));
        }
    };
    let guid = parse_pool_guid(&output, pool)?;
    pin.validate_current(contract)?;
    Ok((guid, output))
}

fn parse_pool_guid(output: &[u8], pool: &str) -> Result<u64, ZfsWorkerError> {
    let text = std::str::from_utf8(output)
        .map_err(|_| ZfsWorkerError::Protocol("held-snapshot pool output is not UTF-8"))?;
    let row = text.strip_suffix('\n').ok_or(ZfsWorkerError::Protocol(
        "held-snapshot pool row is incomplete",
    ))?;
    let (name, guid) = row.split_once('\t').ok_or(ZfsWorkerError::Protocol(
        "held-snapshot pool row is malformed",
    ))?;
    if name != pool || guid.is_empty() || !guid.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ZfsWorkerError::Protocol(
            "held-snapshot pool row is malformed",
        ));
    }
    let value = guid
        .parse::<u64>()
        .map_err(|_| ZfsWorkerError::Protocol("held-snapshot pool GUID is invalid"))?;
    if value == 0 || value.to_string() != guid {
        return Err(ZfsWorkerError::Protocol(
            "held-snapshot pool GUID is invalid",
        ));
    }
    Ok(value)
}

#[cfg(test)]
mod original_response_tests {
    use super::*;

    #[test]
    fn original_response_uses_the_same_full_fields_but_not_the_legacy_header() {
        let request = ObjectDigest::from_bytes([1; 32]);
        let physical = HeldSnapshotPhysicalObservationV1::Matched {
            pool_guid: 9,
            digest: ObjectDigest::from_bytes([2; 32]),
        };
        let legacy = encode_response(request, physical);
        let original = encode_original_response(request, physical);

        assert_eq!(&legacy[10..], &original[10..]);
        assert_eq!(&legacy[..10], b"AOSZHO01\0\x01");
        assert_eq!(&original[..10], b"AOSZHO02\0\x02");
        assert_eq!(decode_response(&legacy, request).unwrap(), physical);
        assert_eq!(decode_original_response(&original, request).unwrap(), physical);
        assert!(decode_response(&original, request).is_err());
        assert!(decode_original_response(&legacy, request).is_err());
    }

    #[test]
    fn original_mismatch_and_wrong_digest_preserve_the_shared_decoder_refusal() {
        let request = ObjectDigest::from_bytes([3; 32]);
        let original = encode_original_response(request, HeldSnapshotPhysicalObservationV1::Mismatch);

        assert_eq!(decode_original_response(&original, request).unwrap(), HeldSnapshotPhysicalObservationV1::Mismatch);
        assert!(decode_original_response(&original, ObjectDigest::from_bytes([4; 32])).is_err());
        assert!(decode_original_response(&original[..82], request).is_err());
        let mut noncanonical = original;
        noncanonical[43] = 1;
        assert!(decode_original_response(&noncanonical, request).is_err());
    }
}

fn encode_text(bytes: &mut Vec<u8>, text: &OsStr) -> Result<(), ZfsWorkerError> {
    let raw = text.as_encoded_bytes();
    let length = u16::try_from(raw.len())
        .map_err(|_| ZfsWorkerError::Protocol("held-snapshot text is too long"))?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(raw);
    Ok(())
}

fn decode_text(decoder: &mut Decoder<'_>) -> Result<String, ZfsWorkerError> {
    let length = usize::from(decoder.u16()?);
    let bytes = decoder.take(length)?;
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| ZfsWorkerError::Protocol("held-snapshot text is not UTF-8"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn fixture() -> (
        ZfsHelperContract,
        ResolvedSnapshot,
        HoldId,
        HeldSnapshotWorkerBindingV1,
    ) {
        let executable = ZfsHelperContract::new("/nix/store/hash-zfs/sbin/zfs".into()).unwrap();
        let root = ManagedDatasetRoot::from_catalog("tank", "tank/aos", 11).unwrap();
        let domains = StorageDomainsV1::new(
            ObjectDigest::from_bytes([1; 32]),
            ObjectDigest::from_bytes([2; 32]),
            ObjectDigest::from_bytes([3; 32]),
            ObjectDigest::from_bytes([4; 32]),
        )
        .unwrap();
        let dataset =
            ResolvedDataset::from_catalog(root, "tank/aos/workspace", 22, [5; 32], domains)
                .unwrap();
        let snapshot = ResolvedSnapshot::from_catalog(dataset, "source", 33, [6; 32]).unwrap();
        let hold_id = HoldId::from_bytes([7; 16]).unwrap();
        let binding = HeldSnapshotWorkerBindingV1 {
            pool_guid: 44,
            catalog: CatalogBindingV1::from_publisher(55, ObjectDigest::from_bytes([8; 32]))
                .unwrap(),
            authority_sequence: 66,
            nonce: [9; 16],
        };
        (executable, snapshot, hold_id, binding)
    }

    #[test]
    fn request_roundtrip_retains_exact_protected_cut_and_nonce() {
        let (executable, snapshot, hold_id, binding) = fixture();
        let bytes = encode_request(&executable, &snapshot, hold_id, binding).unwrap();
        let decoded = decode_request(&bytes).unwrap();

        assert_eq!(decoded.executable, executable);
        assert_eq!(decoded.snapshot, snapshot);
        assert_eq!(decoded.hold_id, hold_id);
        assert_eq!(decoded.binding, binding);
        assert_eq!(decoded.digest, request_digest(&bytes));
        assert!(is_request(&bytes));

        let other_nonce = HeldSnapshotWorkerBindingV1 {
            nonce: [10; 16],
            ..binding
        };
        let next = encode_request(&executable, &snapshot, hold_id, other_nonce).unwrap();
        assert_ne!(request_digest(&bytes), request_digest(&next));
        assert!(decode_request(&bytes[..bytes.len() - 1]).is_err());
        assert!(decode_request(&[bytes.as_slice(), &[0]].concat()).is_err());
    }

    #[test]
    fn response_rejects_replay_and_noncanonical_states() {
        let request = ObjectDigest::from_bytes([1; 32]);
        let digest = ObjectDigest::from_bytes([2; 32]);
        let response = encode_response(
            request,
            HeldSnapshotPhysicalObservationV1::Matched {
                pool_guid: 44,
                digest,
            },
        );
        assert_eq!(
            decode_response(&response, request).unwrap(),
            HeldSnapshotPhysicalObservationV1::Matched {
                pool_guid: 44,
                digest,
            },
        );
        assert!(decode_response(&response, ObjectDigest::from_bytes([3; 32])).is_err());
        assert!(decode_response(&response[..response.len() - 1], request).is_err());
        assert!(decode_response(&[response.as_slice(), &[0]].concat(), request).is_err());

        let mut zero_pool = response;
        zero_pool[43..51].fill(0);
        assert!(decode_response(&zero_pool, request).is_err());
        let mut fake_mismatch = response;
        fake_mismatch[42] = 2;
        assert!(decode_response(&fake_mismatch, request).is_err());
        let mismatch = encode_response(request, HeldSnapshotPhysicalObservationV1::Mismatch);
        assert_eq!(
            decode_response(&mismatch, request).unwrap(),
            HeldSnapshotPhysicalObservationV1::Mismatch,
        );
    }

    #[test]
    fn pool_readback_requires_one_exact_canonical_guid_row() {
        assert_eq!(parse_pool_guid(b"tank\t44\n", "tank").unwrap(), 44);
        for output in [
            b"tank\t0\n".as_slice(),
            b"tank\t044\n",
            b"other\t44\n",
            b"tank\t44\nother\t55\n",
            b"tank\t44",
            b"tank\t+44\n",
            b"tank\t44\tONLINE\n",
        ] {
            assert!(parse_pool_guid(output, "tank").is_err());
        }
    }
}
