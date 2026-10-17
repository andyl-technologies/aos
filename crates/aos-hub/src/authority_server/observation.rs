//! Explicit owner-private local issuer observations, with no authority output.
//!
//! The optional writer observes real queue, signature and commit boundaries.
//! Failed or missing measurements never become zero or an issuer success. Each
//! immutable request handle survives async migration and late blocking commits.
//! The selected source digest requires an independent executable/source join;
//! it is not a build identity inferred by this recorder.

use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::storage_authority::lease::control::IssuerRequest;
use aos_hub_core::storage_authority::lease::{
    LeaseSignatureBoundary, LeaseSignatureKind, LeaseSignatureObservation,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest as _, Sha256};

use super::AuthorityConfiguration;

const MAX_RECORD_BYTES: usize = 1024;
const MAX_RECORDS: u64 = 262_144;
const MAX_OUTPUT_BYTES: u64 = 256 * 1024 * 1024;

#[cfg(test)]
mod tests;

/// Explicit local qualification recording inputs, separate from issuer policy.
///
/// This selects no authority input and changes no permission. Source provenance
/// still requires the external collector's exact executable/build join.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalIssuerObservationConfiguration {
    /// Fresh lowercase hexadecimal run identity.
    pub run_id: String,
    /// Independently selected build-source commitment, never inferred here.
    pub selected_source_sha256: String,
    /// Exact running executable SHA-256 required before recording.
    pub executable_sha256: String,
    /// Exact canonical loaded authority configuration SHA-256.
    pub authority_configuration_sha256: String,
    /// New private output under a separate existing owner-private directory.
    pub output: PathBuf,
}

impl LocalIssuerObservationConfiguration {
    /// Reads explicit observation configuration from existing private custody.
    ///
    /// # Errors
    /// Returns an error for insecure input, unknown fields or unavailable bytes.
    pub fn read(path: &Path) -> Result<Self> {
        let bytes = crate::auth::seal::read_secret_file_zeroizing(path)?;
        Ok(serde_json::from_slice(&bytes)?)
    }
}

#[derive(Clone)]
pub(crate) struct Observation {
    writer: Arc<Mutex<Writer>>,
    request: Option<RequestPins>,
}

impl std::fmt::Debug for Observation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Observation { private_output: [REDACTED] }")
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct RequestPins {
    nonce: String,
    request_digest: String,
    received_body_sha256: String,
    received_body_bytes: usize,
    #[serde(skip)]
    _lifetime: Arc<RequestLifetime>,
}

struct RequestLifetime {
    writer: Arc<Mutex<Writer>>,
}

impl Drop for RequestLifetime {
    fn drop(&mut self) {
        if let Ok(mut writer) = self.writer.lock() {
            match writer.active_requests.checked_sub(1) {
                Some(remaining) => writer.active_requests = remaining,
                None => writer.failed = true,
            }
        }
    }
}

struct Writer {
    file: File,
    path: PathBuf,
    device: u64,
    inode: u64,
    parent_device: u64,
    parent_inode: u64,
    sequence: u64,
    bytes: u64,
    failed: bool,
    finished: bool,
    active_requests: u64,
    started: Instant,
}

impl Observation {
    pub(super) fn open(
        selected: &LocalIssuerObservationConfiguration,
        authority: &AuthorityConfiguration,
    ) -> Result<Self> {
        ensure!(
            hexadecimal(&selected.run_id, 32),
            "invalid observation run identity"
        );
        for digest in [
            &selected.selected_source_sha256,
            &selected.executable_sha256,
            &selected.authority_configuration_sha256,
        ] {
            ensure!(hexadecimal(digest, 64), "invalid observation commitment");
        }
        let configuration_digest = hex::encode(Sha256::digest(serde_json::to_vec(authority)?));
        ensure!(
            configuration_digest == selected.authority_configuration_sha256,
            "selected authority configuration differs"
        );
        let executable_digest = running_executable_digest()?;
        let (process_pid, process_start_ticks) = running_process_identity()?;
        ensure!(
            executable_digest == selected.executable_sha256,
            "running issuer differs"
        );

        let path = &selected.output;
        ensure!(path.is_absolute(), "observation path must be absolute");
        ensure!(
            ![
                &authority.publisher_key_file,
                &authority.renewal_key_file,
                &authority.signing_seed_file,
            ]
            .contains(&path),
            "observation output conflicts with a credential path"
        );
        let parent = path.parent().context("observation directory is absent")?;
        ensure!(
            std::fs::canonicalize(parent)? == parent
                && authority.journal_file.parent() != Some(parent)
                && !parent.starts_with(&authority.hub_root),
            "observation output must have separate private custody"
        );
        let directory = std::fs::symlink_metadata(parent)?;
        ensure!(
            directory.is_dir()
                && directory.uid() == rustix::process::geteuid().as_raw()
                && directory.mode() & 0o777 == 0o700,
            "observation directory is not owner-private"
        );
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(path)?;
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file()
                && metadata.uid() == directory.uid()
                && metadata.mode() & 0o777 == 0o600,
            "observation file is not private"
        );
        let observation = Self {
            writer: Arc::new(Mutex::new(Writer {
                file,
                path: path.clone(),
                device: metadata.dev(),
                inode: metadata.ino(),
                parent_device: directory.dev(),
                parent_inode: directory.ino(),
                sequence: 0,
                bytes: 0,
                failed: false,
                finished: false,
                active_requests: 0,
                started: Instant::now(),
            })),
            request: None,
        };
        observation.record("opened", json!({
            "runId": selected.run_id,
            "selectedSourceSha256": selected.selected_source_sha256,
            "executableSha256": executable_digest,
            "authorityConfigurationSha256": configuration_digest,
            "installationSha256": hex::encode(Sha256::digest(serde_json::to_vec(&authority.installation)?)),
            "maximumRecordBytes": MAX_RECORD_BYTES,
            "maximumRecords": MAX_RECORDS,
            "maximumOutputBytes": MAX_OUTPUT_BYTES,
            "processCpuNs": cpu_sample(rustix::time::ClockId::ProcessCPUTime),
            "processPid": process_pid,
            "processStartTicks": process_start_ticks,
        }));
        ensure!(observation.healthy(), "observation header was not retained");
        Ok(observation)
    }

    pub(super) fn for_request(&self, request: &IssuerRequest, body: &[u8]) -> Result<Self> {
        ensure!(
            hexadecimal(&request.nonce, 64),
            "observation nonce shape differs"
        );
        let request_digest = request.digest()?;
        {
            let mut writer = self
                .writer
                .lock()
                .map_err(|_| anyhow::anyhow!("observation lock poisoned"))?;
            writer.active_requests = writer
                .active_requests
                .checked_add(1)
                .context("observation request overflow")?;
        }
        Ok(Self {
            writer: self.writer.clone(),
            request: Some(RequestPins {
                nonce: request.nonce.clone(),
                request_digest,
                received_body_sha256: hex::encode(Sha256::digest(body)),
                received_body_bytes: body.len(),
                _lifetime: Arc::new(RequestLifetime {
                    writer: self.writer.clone(),
                }),
            }),
        })
    }

    pub(crate) fn record(&self, event: &str, fields: serde_json::Value) {
        let Ok(mut writer) = self.writer.lock() else {
            return;
        };
        if writer.failed || writer.finished {
            return;
        }
        if writer
            .write_record(event, self.request.as_ref(), fields)
            .is_err()
        {
            // Authority results are unaffected. A missing/failed terminal marker
            // makes the whole observation window unusable for qualification.
            writer.failed = true;
        }
    }

    pub(super) fn healthy(&self) -> bool {
        self.writer.lock().is_ok_and(|writer| !writer.failed)
    }

    pub(super) fn invalidate(&self) {
        if let Ok(mut writer) = self.writer.lock() {
            writer.failed = true;
        }
    }

    pub(super) fn finish(&self) -> Result<()> {
        let mut writer = self
            .writer
            .lock()
            .map_err(|_| anyhow::anyhow!("observation lock poisoned"))?;
        ensure!(
            !writer.failed && !writer.finished,
            "observation window is unavailable"
        );
        if writer.active_requests != 0 {
            // A cancelled handler may still own blocking SQLite work. Refuse
            // a healthy footer rather than asserting that the work drained.
            writer.failed = true;
            anyhow::bail!("observation request work is still held");
        }
        let records = writer.sequence;
        let bytes = writer.bytes;
        let window_wall_ns = elapsed_ns(writer.started);
        let result = writer
            .write_record(
                "finished",
                None,
                json!({
                    "precedingRecords": records, "precedingBytes": bytes,
                    "processCpuNs": cpu_sample(rustix::time::ClockId::ProcessCPUTime),
                    "processWindowWallNs": window_wall_ns,
                }),
            )
            .and_then(|()| writer.file.sync_all().map_err(Into::into));
        writer.failed = result.is_err();
        writer.finished = true;
        // Footer bytes alone cannot prove a successful final sync. The actual
        // serving exit must be joined independently before using this window.
        result.context("finishing private issuer observation")
    }

    pub(super) fn signature_observer(&self) -> impl FnMut(LeaseSignatureObservation) + '_ {
        let mut started: Option<(LeaseSignatureKind, Instant, Option<u64>)> = None;
        move |event| match event.boundary {
            LeaseSignatureBoundary::Started => {
                started = Some((
                    event.kind,
                    Instant::now(),
                    cpu_sample(rustix::time::ClockId::ThreadCPUTime),
                ));
            }
            LeaseSignatureBoundary::Completed => {
                let ended_cpu = cpu_sample(rustix::time::ClockId::ThreadCPUTime);
                let sample = started.take().filter(|(kind, _, _)| *kind == event.kind);
                let (wall, cpu) = sample.map_or((None, None), |(_, at, before)| {
                    (
                        u64::try_from(at.elapsed().as_nanos()).ok(),
                        before
                            .zip(ended_cpu)
                            .and_then(|(first, last)| last.checked_sub(first)),
                    )
                });
                self.record("signature", json!({
                    "purpose": match event.kind { LeaseSignatureKind::Lease => "lease", LeaseSignatureKind::Reply => "reply" },
                    "wallNs": wall, "threadCpuNs": cpu,
                }));
            }
        }
    }
}

impl Writer {
    fn write_record(
        &mut self,
        event: &str,
        request: Option<&RequestPins>,
        fields: serde_json::Value,
    ) -> Result<()> {
        let parent = self
            .path
            .parent()
            .context("observation parent disappeared")?;
        let directory = std::fs::symlink_metadata(parent)?;
        let metadata = std::fs::symlink_metadata(&self.path)?;
        ensure!(
            directory.dev() == self.parent_device
                && directory.ino() == self.parent_inode
                && directory.is_dir()
                && directory.mode() & 0o777 == 0o700
                && directory.uid() == rustix::process::geteuid().as_raw()
                && metadata.dev() == self.device
                && metadata.ino() == self.inode
                && metadata.is_file()
                && metadata.mode() & 0o777 == 0o600
                && metadata.uid() == directory.uid()
                && metadata.nlink() == 1
                && metadata.len() == self.bytes,
            "observation custody changed"
        );
        let sequence = self
            .sequence
            .checked_add(1)
            .context("observation sequence overflow")?;
        let mut bytes = serde_json::to_vec(&json!({
            "version": 1, "sequence": sequence, "atUnixNs": unix_ns(),
            "event": event, "request": request, "fields": fields,
        }))?;
        bytes.push(b'\n');
        let length = u64::try_from(bytes.len())?;
        let total = self
            .bytes
            .checked_add(length)
            .context("observation byte overflow")?;
        ensure!(
            bytes.len() <= MAX_RECORD_BYTES && sequence <= MAX_RECORDS && total <= MAX_OUTPUT_BYTES,
            "observation bound exhausted"
        );
        self.file.write_all(&bytes)?;
        self.sequence = sequence;
        self.bytes = total;
        Ok(())
    }
}

pub(super) struct RequestOutcome {
    observer: Option<Observation>,
    started: Option<Instant>,
    completed: bool,
}

impl RequestOutcome {
    pub(super) fn new(observer: Option<Observation>) -> Self {
        if let Some(observer) = &observer {
            observer.record("request_started", json!({}));
        }
        let started = observer.as_ref().map(|_| Instant::now());
        Self {
            observer,
            started,
            completed: false,
        }
    }

    pub(super) fn completed(&mut self, success: bool) {
        if let Some(observer) = &self.observer {
            observer.record(
                "request_completed",
                json!({
                    "outcome": if success { "success" } else { "refused" },
                    "wallNs": self.started.and_then(elapsed_ns),
                }),
            );
        }
        self.completed = true;
    }
}

impl Drop for RequestOutcome {
    fn drop(&mut self) {
        if !self.completed {
            if let Some(observer) = &self.observer {
                observer.record(
                    "request_abandoned",
                    json!({
                        "wallNs": self.started.and_then(elapsed_ns),
                        "settlement": "unknown",
                    }),
                );
            }
        }
    }
}

pub(crate) fn elapsed_ns(started: Instant) -> Option<u64> {
    u64::try_from(started.elapsed().as_nanos()).ok()
}

fn cpu_sample(clock: rustix::time::ClockId) -> Option<u64> {
    let value =
        rustix::time::clock_gettime_dynamic(rustix::time::DynamicClockId::Known(clock)).ok()?;
    let seconds = u64::try_from(value.tv_sec).ok()?;
    let nanoseconds = u64::try_from(value.tv_nsec)
        .ok()
        .filter(|value| *value < 1_000_000_000)?;
    seconds.checked_mul(1_000_000_000)?.checked_add(nanoseconds)
}

fn unix_ns() -> Option<String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|value| value.as_nanos().to_string())
}

fn hexadecimal(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn running_executable_digest() -> Result<String> {
    let mut file = File::open("/proc/self/exe")?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() <= 512 * 1024 * 1024,
        "issuer executable exceeds bound"
    );
    let mut hasher = Sha256::new();
    let mut bytes = [0u8; 64 * 1024];
    loop {
        let count = file.read(&mut bytes)?;
        if count == 0 {
            break;
        }
        hasher.update(&bytes[..count]);
    }
    let after = file.metadata()?;
    ensure!(
        metadata.len() == after.len()
            && metadata.mtime() == after.mtime()
            && metadata.mtime_nsec() == after.mtime_nsec(),
        "issuer executable changed"
    );
    Ok(hex::encode(hasher.finalize()))
}

fn running_process_identity() -> Result<(u32, String)> {
    let mut bytes = String::new();
    File::open("/proc/self/stat")?
        .take(4097)
        .read_to_string(&mut bytes)?;
    ensure!(bytes.len() <= 4096, "issuer process identity exceeds bound");
    let (prefix, tail) = bytes
        .rsplit_once(") ")
        .context("issuer process identity is unavailable")?;
    let pid = std::process::id();
    ensure!(
        prefix
            .split_once(' ')
            .is_some_and(|(actual, _)| actual == pid.to_string()),
        "issuer process identity differs"
    );
    let ticks = tail
        .split_whitespace()
        .nth(19)
        .context("issuer process lifetime is absent")?;
    ensure!(
        !ticks.is_empty() && ticks.len() <= 20 && ticks.bytes().all(|byte| byte.is_ascii_digit()),
        "issuer process lifetime differs"
    );
    ticks.parse::<u64>()?;
    Ok((pid, ticks.to_owned()))
}
