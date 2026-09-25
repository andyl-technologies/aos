//! Live direct/delta checkpoint equivalence and dirty-epoch flight.
//!
//! The harness attaches to a dedicated QEMU that is already stopped at a
//! Crucible exact simulator boundary. It never starts or stops QEMU itself.
//! Set `AOS_CHECKPOINT_DELTA_QMP` and `AOS_CHECKPOINT_DELTA_QTEST` to its QMP
//! and qtest Unix sockets to run the flight. `AOS_CHECKPOINT_DELTA_GPA` may
//! override the default writable guest-physical test page at `0x110000` for
//! the host-write flight. The guest-write flight requires the fixture's fixed
//! `0x110000` target.
//!
//! This focused flight covers cached and freshly-filled guest TLB writes, host
//! qtest dirty writes, direct/multi-delta byte equivalence, empty and
//! post-restore epochs, abort retention, stale commit, quota failure, restore,
//! and ordinary-mode rejection without output or epoch mutation. Other
//! device/DMA dirty sources, cancellation, malformed parent/hash/topology
//! inputs, and post-mutation restore failure invalidation remain separate
//! native matrix cases.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::env;
use std::error::Error;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::thread;
use std::time::Duration;

use crate::{
    QemuQmpVmStateControlChannel, QmpCheckpointCapture, QmpCheckpointCaptureRequest,
    QmpCheckpointIdentity, QmpCheckpointRamKind, QmpCheckpointRestoreLayer,
    QmpCheckpointRestoreRequest, QmpDescriptorName, QmpRunStateKind,
};
use crucible::ContentHash;
use rustix::fs::{MemfdFlags, SealFlags, fcntl_add_seals, memfd_create};
use rustix::time::{ClockId, clock_gettime};

#[path = "checkpoint_delta_flight_support.rs"]
mod support;

use support::*;

const QMP_PATH_ENV: &str = "AOS_CHECKPOINT_DELTA_QMP";
const QTEST_PATH_ENV: &str = "AOS_CHECKPOINT_DELTA_QTEST";
const TEST_GPA_ENV: &str = "AOS_CHECKPOINT_DELTA_GPA";
const DEFAULT_TEST_GPA: u64 = 0x11_0000;
const GUEST_TLB_MODE_GPA: u64 = 0x10_2000;
const GUEST_PAGE_TABLES_GPA: u64 = 0x10_b000;
const PAGE_BYTES: usize = 4096;
const GUEST_PAGE_TABLES_BYTES: usize = PAGE_BYTES * 2;
const RAM_CEILING: u64 = 1 << 30;
const DEVICE_CEILING: u64 = 1 << 28;
const QTEST_TIMEOUT: Duration = Duration::from_secs(10);
const QTEST_RESPONSE_MAX_BYTES: usize = 1 << 20;
const QTEST_ASYNC_LINE_MAX: usize = 1024;
const EXACT_STOP_POLL_LIMIT: usize = 600;
const EXACT_STOP_POLL_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Debug)]
struct CapturedArtifact {
    report: QmpCheckpointCapture,
    ram_file: File,
    ram_bytes: Vec<u8>,
    ram_hash: ContentHash,
    device_file: File,
    device_bytes: Vec<u8>,
    device_hash: ContentHash,
}

#[derive(Debug)]
struct RamLayer {
    kind: QmpCheckpointRamKind,
    page_size: u32,
    regions: Vec<RamRegion>,
    records: Vec<RamRecord>,
}

#[derive(Debug)]
struct RamRegion {
    name: String,
    length: u64,
}

#[derive(Debug)]
struct RamRecord {
    region: usize,
    offset: u64,
    bytes: Vec<u8>,
}

#[derive(Debug)]
struct QtestClient {
    stream: BufReader<UnixStream>,
}

impl QtestClient {
    fn connect(path: &Path) -> Result<Self, Box<dyn Error>> {
        let stream = UnixStream::connect(path)?;
        stream.set_read_timeout(Some(QTEST_TIMEOUT))?;
        stream.set_write_timeout(Some(QTEST_TIMEOUT))?;
        Ok(Self {
            stream: BufReader::new(stream),
        })
    }

    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
        writeln!(
            self.stream.get_mut(),
            "write 0x{address:x} 0x{:x} 0x{}",
            bytes.len(),
            hex_bytes(bytes)
        )?;
        self.stream.get_mut().flush()?;
        let response = self.response()?;
        if response != "OK" {
            return Err(format!("qtest write failed: {response}").into());
        }
        let observed = self.read(address, bytes.len())?;
        if observed != bytes {
            return Err(format!("qtest write readback differs at 0x{address:x}").into());
        }
        Ok(())
    }

    fn read(&mut self, address: u64, length: usize) -> Result<Vec<u8>, Box<dyn Error>> {
        writeln!(self.stream.get_mut(), "read 0x{address:x} 0x{length:x}")?;
        self.stream.get_mut().flush()?;
        let response = self.response()?;
        let encoded = response
            .strip_prefix("OK 0x")
            .ok_or_else(|| format!("qtest read failed: {response}"))?;
        decode_hex(encoded)
    }

    fn response(&mut self) -> Result<String, Box<dyn Error>> {
        for _ in 0..QTEST_ASYNC_LINE_MAX {
            let line = self.bounded_line()?;
            let line = line.trim_end();
            if line.starts_with("OK") || line.starts_with("FAIL") || line.starts_with("ERR") {
                return Ok(line.to_owned());
            }
        }
        Err("qtest exceeded its asynchronous response-line bound".into())
    }

    fn bounded_line(&mut self) -> Result<String, Box<dyn Error>> {
        let mut line = Vec::new();
        loop {
            let available = self.stream.fill_buf()?;
            if available.is_empty() {
                return Err("qtest closed before its response".into());
            }
            let consumed = available
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(available.len(), |index| index + 1);
            if consumed > QTEST_RESPONSE_MAX_BYTES - line.len() {
                return Err("qtest response line exceeds its byte bound".into());
            }
            let complete = available[consumed - 1] == b'\n';
            line.extend_from_slice(&available[..consumed]);
            self.stream.consume(consumed);
            if complete {
                return Ok(String::from_utf8(line)?);
            }
        }
    }
}

#[test]
#[ignore = "requires an explicitly dedicated paused Crucible QEMU fixture"]
fn live_direct_delta_restore_preserves_exact_bytes_and_dirty_epochs() -> Result<(), Box<dyn Error>>
{
    let qmp_path = env::var_os(QMP_PATH_ENV)
        .ok_or_else(|| format!("{QMP_PATH_ENV} must name the dedicated fixture QMP socket"))?;
    let qtest_path = env::var_os(QTEST_PATH_ENV)
        .ok_or_else(|| format!("{QTEST_PATH_ENV} must name the dedicated fixture qtest socket"))?;

    let qmp_stream = UnixStream::connect(&qmp_path)?;
    let mut qmp = QemuQmpVmStateControlChannel::connect(qmp_stream)?;
    let mut qtest = QtestClient::connect(Path::new(&qtest_path))?;
    let test_gpa = test_gpa()?;
    if test_gpa != DEFAULT_TEST_GPA {
        return Err(format!(
            "{TEST_GPA_ENV} must be 0x{DEFAULT_TEST_GPA:x} for the guest-write fixture"
        )
        .into());
    }

    // The first plugin stop occurs during fixture startup. Reach the guest's
    // write loop before taking the direct baseline so setup dirt does not
    // weaken the per-epoch record assertions below.
    let initial_page = qtest.read(test_gpa, PAGE_BYTES)?;
    let direct_page = resume_until_page_changes(&mut qmp, &mut qtest, test_gpa, &initial_page)?;

    let direct_identity = identity(0x10);
    let guest_first_identity = identity(0x18);
    let guest_second_identity = identity(0x19);
    let fresh_first_identity = identity(0x1a);
    let fresh_second_identity = identity(0x1b);
    let first_identity = identity(0x20);
    let second_identity = identity(0x30);
    let third_identity = identity(0x40);

    let direct = capture(
        &mut qmp,
        0,
        QmpCheckpointRamKind::Direct,
        direct_identity,
        None,
        RAM_CEILING,
    )?;
    let committed = qmp.commit_exact_checkpoint(direct_identity)?;
    assert_eq!(committed.committed(), Some(direct_identity));
    assert_eq!(committed.epoch_generation(), 1);

    // Consecutive writes through the cached TLB require every commit to re-arm
    // that page after clearing only the private checkpoint dirty client.
    resume_to_exact_boundary(&mut qmp)?;
    let guest_first_page = qtest.read(test_gpa, PAGE_BYTES)?;
    let guest_first_page_tables_before =
        qtest.read(GUEST_PAGE_TABLES_GPA, GUEST_PAGE_TABLES_BYTES)?;
    assert_ne!(guest_first_page, direct_page);
    let guest_first = capture(
        &mut qmp,
        1,
        QmpCheckpointRamKind::Delta,
        guest_first_identity,
        Some(direct_identity),
        RAM_CEILING,
    )?;
    let guest_first_page_tables = qtest.read(GUEST_PAGE_TABLES_GPA, GUEST_PAGE_TABLES_BYTES)?;
    assert_bytes_equal(
        &guest_first_page_tables,
        &guest_first_page_tables_before,
        "cached first page tables changed during capture",
    );
    // A protected TLB refill probes page-table entries as stores before
    // deciding whether their A/D bits need changing. The probe conservatively
    // dirties both adjacent pages, which the serializer coalesces into one
    // record whose exact bytes are part of the contract.
    assert_exact_page_delta(
        &guest_first,
        &[
            (GUEST_PAGE_TABLES_GPA, &guest_first_page_tables),
            (test_gpa, &guest_first_page),
        ],
        "cached first",
    )?;
    qmp.commit_exact_checkpoint(guest_first_identity)?;

    resume_to_exact_boundary(&mut qmp)?;
    let guest_second_page = qtest.read(test_gpa, PAGE_BYTES)?;
    assert_ne!(guest_second_page, guest_first_page);
    let guest_second = capture(
        &mut qmp,
        2,
        QmpCheckpointRamKind::Delta,
        guest_second_identity,
        Some(guest_first_identity),
        RAM_CEILING,
    )?;
    assert_exact_page_delta(
        &guest_second,
        &[(test_gpa, &guest_second_page)],
        "cached second",
    )?;
    qmp.commit_exact_checkpoint(guest_second_identity)?;

    restore(
        &mut qmp,
        [&direct, &guest_first, &guest_second],
        &guest_second,
        guest_second_identity,
    )?;
    assert_eq!(qtest.read(test_gpa, PAGE_BYTES)?, guest_second_page);

    // The second phase reloads CR3 before each write. The target is a
    // dedicated non-code page whose VGA, code, and migration clients are all
    // dirty, so the private clean client must make each fresh TLB fill trap.
    qtest.write(GUEST_TLB_MODE_GPA, &[1])?;
    resume_to_exact_boundary(&mut qmp)?;
    let fresh_first_page = qtest.read(test_gpa, PAGE_BYTES)?;
    assert_ne!(fresh_first_page, guest_second_page);
    let fresh_first = capture(
        &mut qmp,
        3,
        QmpCheckpointRamKind::Delta,
        fresh_first_identity,
        Some(guest_second_identity),
        RAM_CEILING,
    )?;
    let fresh_mode_page = qtest.read(GUEST_TLB_MODE_GPA, PAGE_BYTES)?;
    let fresh_first_page_tables = qtest.read(GUEST_PAGE_TABLES_GPA, GUEST_PAGE_TABLES_BYTES)?;
    assert_exact_page_delta(
        &fresh_first,
        &[
            (GUEST_TLB_MODE_GPA, &fresh_mode_page),
            (GUEST_PAGE_TABLES_GPA, &fresh_first_page_tables),
            (test_gpa, &fresh_first_page),
        ],
        "fresh first",
    )?;
    qmp.commit_exact_checkpoint(fresh_first_identity)?;

    resume_to_exact_boundary(&mut qmp)?;
    let fresh_second_page = qtest.read(test_gpa, PAGE_BYTES)?;
    assert_ne!(fresh_second_page, fresh_first_page);
    let fresh_second = capture(
        &mut qmp,
        4,
        QmpCheckpointRamKind::Delta,
        fresh_second_identity,
        Some(fresh_first_identity),
        RAM_CEILING,
    )?;
    let fresh_second_page_tables = qtest.read(GUEST_PAGE_TABLES_GPA, GUEST_PAGE_TABLES_BYTES)?;
    assert_exact_page_delta(
        &fresh_second,
        &[
            (GUEST_PAGE_TABLES_GPA, &fresh_second_page_tables),
            (test_gpa, &fresh_second_page),
        ],
        "fresh second",
    )?;
    qmp.commit_exact_checkpoint(fresh_second_identity)?;

    restore(
        &mut qmp,
        [
            &direct,
            &guest_first,
            &guest_second,
            &fresh_first,
            &fresh_second,
        ],
        &fresh_second,
        fresh_second_identity,
    )?;
    assert_eq!(qtest.read(test_gpa, PAGE_BYTES)?, fresh_second_page);

    let first_page = patterned_page(0x51);
    qtest.write(test_gpa, &first_page)?;
    let first_aborted = capture(
        &mut qmp,
        5,
        QmpCheckpointRamKind::Delta,
        first_identity,
        Some(fresh_second_identity),
        RAM_CEILING,
    )?;
    assert!(first_aborted.report.ram_records() > 0);
    let aborted = qmp.abort_exact_checkpoint(first_identity, Some(fresh_second_identity))?;
    assert_eq!(aborted.epoch_generation(), 7);

    let first_stale = capture(
        &mut qmp,
        6,
        QmpCheckpointRamKind::Delta,
        first_identity,
        Some(fresh_second_identity),
        RAM_CEILING,
    )?;
    assert_eq!(first_stale.ram_bytes, first_aborted.ram_bytes);
    assert_eq!(first_stale.device_bytes, first_aborted.device_bytes);

    let candidate_write = patterned_page(0x62);
    qtest.write(test_gpa + PAGE_BYTES as u64, &candidate_write)?;
    assert!(qmp.commit_exact_checkpoint(first_identity).is_err());
    let stale_epoch = qmp.query_exact_checkpoint_epoch()?;
    assert_eq!(stale_epoch.committed(), Some(fresh_second_identity));
    assert_eq!(stale_epoch.candidate(), Some(first_identity));
    qmp.abort_exact_checkpoint(first_identity, Some(fresh_second_identity))?;

    let first = capture(
        &mut qmp,
        7,
        QmpCheckpointRamKind::Delta,
        first_identity,
        Some(fresh_second_identity),
        RAM_CEILING,
    )?;
    assert!(first.report.ram_records() > 0);
    qmp.commit_exact_checkpoint(first_identity)?;

    let second_page = patterned_page(0x73);
    qtest.write(test_gpa + (PAGE_BYTES * 2) as u64, &second_page)?;
    assert!(
        capture(
            &mut qmp,
            8,
            QmpCheckpointRamKind::Delta,
            second_identity,
            Some(first_identity),
            1
        )
        .is_err()
    );
    let failed_epoch = qmp.query_exact_checkpoint_epoch()?;
    assert_eq!(failed_epoch.committed(), Some(first_identity));
    assert_eq!(failed_epoch.candidate(), None);

    let second = capture(
        &mut qmp,
        9,
        QmpCheckpointRamKind::Delta,
        second_identity,
        Some(first_identity),
        RAM_CEILING,
    )?;
    assert!(second.report.ram_records() > 0);
    qmp.commit_exact_checkpoint(second_identity)?;

    let third_page = patterned_page(0x84);
    qtest.write(test_gpa + (PAGE_BYTES * 3) as u64, &third_page)?;
    let third = capture(
        &mut qmp,
        10,
        QmpCheckpointRamKind::Delta,
        third_identity,
        Some(second_identity),
        RAM_CEILING,
    )?;
    qmp.commit_exact_checkpoint(third_identity)?;

    let direct_probe_identity = identity(0x50);
    let direct_probe = capture(
        &mut qmp,
        11,
        QmpCheckpointRamKind::Direct,
        direct_probe_identity,
        None,
        RAM_CEILING,
    )?;
    let reconstructed = reconstruct([
        &direct,
        &guest_first,
        &guest_second,
        &fresh_first,
        &fresh_second,
        &first,
        &second,
        &third,
    ])?;
    assert_eq!(reconstructed, reconstruct([&direct_probe])?);
    assert_eq!(third.device_bytes, direct_probe.device_bytes);
    qmp.abort_exact_checkpoint(direct_probe_identity, Some(third_identity))?;

    qtest.write(test_gpa, &patterned_page(0xa5))?;
    restore(
        &mut qmp,
        [
            &direct,
            &guest_first,
            &guest_second,
            &fresh_first,
            &fresh_second,
            &first,
            &second,
            &third,
        ],
        &third,
        third_identity,
    )?;
    assert_eq!(qtest.read(test_gpa, PAGE_BYTES)?, first_page);
    assert_eq!(
        qtest.read(test_gpa + PAGE_BYTES as u64, PAGE_BYTES)?,
        candidate_write
    );
    assert_eq!(
        qtest.read(test_gpa + (PAGE_BYTES * 2) as u64, PAGE_BYTES)?,
        second_page
    );
    assert_eq!(
        qtest.read(test_gpa + (PAGE_BYTES * 3) as u64, PAGE_BYTES)?,
        third_page
    );

    let empty_identity = identity(0x55);
    let empty = capture(
        &mut qmp,
        12,
        QmpCheckpointRamKind::Delta,
        empty_identity,
        Some(third_identity),
        RAM_CEILING,
    )?;
    assert_eq!(empty.report.ram_records(), 0);
    qmp.abort_exact_checkpoint(empty_identity, Some(third_identity))?;

    let post_restore_page = patterned_page(0x96);
    qtest.write(test_gpa + (PAGE_BYTES * 4) as u64, &post_restore_page)?;
    let post_restore_identity = identity(0x58);
    let post_restore = capture(
        &mut qmp,
        13,
        QmpCheckpointRamKind::Delta,
        post_restore_identity,
        Some(third_identity),
        RAM_CEILING,
    )?;
    assert_eq!(post_restore.report.ram_records(), 1);
    assert_eq!(parse_ram_layer(&post_restore.ram_bytes)?.records.len(), 1);
    qmp.abort_exact_checkpoint(post_restore_identity, Some(third_identity))?;

    restore(
        &mut qmp,
        [
            &direct,
            &guest_first,
            &guest_second,
            &fresh_first,
            &fresh_second,
            &first,
            &second,
            &third,
        ],
        &third,
        third_identity,
    )?;

    let restored_probe_identity = identity(0x60);
    let restored_probe = capture(
        &mut qmp,
        14,
        QmpCheckpointRamKind::Direct,
        restored_probe_identity,
        None,
        RAM_CEILING,
    )?;
    assert_eq!(reconstructed, reconstruct([&restored_probe])?);
    assert_eq!(third.device_bytes, restored_probe.device_bytes);
    qmp.abort_exact_checkpoint(restored_probe_identity, Some(third_identity))?;

    let direct_restore_to_runnable =
        measure_restore_to_runnable(&mut qmp, [&direct], &direct, direct_identity)?;
    wait_for_exact_boundary(&mut qmp)?;
    let delta_restore_to_runnable = measure_restore_to_runnable(
        &mut qmp,
        [
            &direct,
            &guest_first,
            &guest_second,
            &fresh_first,
            &fresh_second,
            &first,
            &second,
            &third,
        ],
        &third,
        third_identity,
    )?;
    wait_for_exact_boundary(&mut qmp)?;

    println!(
        "direct_restore_to_runnable_us={}",
        direct_restore_to_runnable.as_micros().max(1)
    );
    println!(
        "delta_restore_to_runnable_us={}",
        delta_restore_to_runnable.as_micros().max(1)
    );
    println!("restore_latency_measurement=descriptor-restore-through-cont-ack");
    Ok(())
}

#[test]
#[ignore = "requires an explicitly dedicated paused ordinary-TCG QEMU fixture"]
fn ordinary_mode_checkpoint_rejection_is_inert() -> Result<(), Box<dyn Error>> {
    let qmp_path = env::var_os(QMP_PATH_ENV)
        .ok_or_else(|| format!("{QMP_PATH_ENV} must name the dedicated fixture QMP socket"))?;
    let qtest_path = env::var_os(QTEST_PATH_ENV)
        .ok_or_else(|| format!("{QTEST_PATH_ENV} must name the dedicated fixture qtest socket"))?;

    let qmp_stream = UnixStream::connect(&qmp_path)?;
    let mut qmp = QemuQmpVmStateControlChannel::connect(qmp_stream)?;
    let mut qtest = QtestClient::connect(Path::new(&qtest_path))?;
    let test_gpa = test_gpa()?;

    let before_epoch = qmp.query_exact_checkpoint_epoch()?;
    assert_eq!(before_epoch.epoch_generation(), 0);
    assert_eq!(before_epoch.committed(), None);
    assert_eq!(before_epoch.candidate(), None);

    let expected_page = patterned_page(0xb7);
    qtest.write(test_gpa, &expected_page)?;

    let ram_name = QmpDescriptorName::new("ordinary-ram")?;
    let device_name = QmpDescriptorName::new("ordinary-device")?;
    let cancellation_name = QmpDescriptorName::new("ordinary-cancel")?;
    let ram_file = File::from(memfd_create(
        "ordinary-checkpoint-ram",
        MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
    )?);
    let device_file = File::from(memfd_create(
        "ordinary-checkpoint-device",
        MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
    )?);
    let (cancellation, _cancellation_peer) = UnixStream::pair()?;

    qmp.install_exact_checkpoint_descriptor(&ram_name, ram_file.as_fd())?;
    qmp.install_exact_checkpoint_descriptor(&device_name, device_file.as_fd())?;
    qmp.install_exact_checkpoint_descriptor(&cancellation_name, cancellation.as_fd())?;
    let request = QmpCheckpointCaptureRequest::direct(
        identity(0x70),
        ram_name,
        device_name,
        cancellation_name,
        RAM_CEILING,
        DEVICE_CEILING,
    )?;
    assert!(qmp.capture_exact_checkpoint(&request).is_err());

    assert_eq!(ram_file.metadata()?.len(), 0);
    assert_eq!(device_file.metadata()?.len(), 0);
    assert_eq!(qtest.read(test_gpa, PAGE_BYTES)?, expected_page);

    let after_epoch = qmp.query_exact_checkpoint_epoch()?;
    assert_eq!(after_epoch, before_epoch);
    Ok(())
}

fn capture(
    qmp: &mut QemuQmpVmStateControlChannel<UnixStream>,
    sequence: u32,
    kind: QmpCheckpointRamKind,
    candidate: QmpCheckpointIdentity,
    parent: Option<QmpCheckpointIdentity>,
    maximum_ram_bytes: u64,
) -> Result<CapturedArtifact, Box<dyn Error>> {
    let ram_name = QmpDescriptorName::new(format!("delta-ram-{sequence}"))?;
    let device_name = QmpDescriptorName::new(format!("delta-device-{sequence}"))?;
    let cancellation_name = QmpDescriptorName::new(format!("delta-cancel-{sequence}"))?;
    let mut ram_file = File::from(memfd_create(
        format!("checkpoint-ram-{sequence}"),
        MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
    )?);
    let mut device_file = File::from(memfd_create(
        format!("checkpoint-device-{sequence}"),
        MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
    )?);
    let (cancellation, _cancellation_peer) = UnixStream::pair()?;

    qmp.install_exact_checkpoint_descriptor(&ram_name, ram_file.as_fd())?;
    qmp.install_exact_checkpoint_descriptor(&device_name, device_file.as_fd())?;
    qmp.install_exact_checkpoint_descriptor(&cancellation_name, cancellation.as_fd())?;
    let request = match (kind, parent) {
        (QmpCheckpointRamKind::Direct, None) => QmpCheckpointCaptureRequest::direct(
            candidate,
            ram_name,
            device_name,
            cancellation_name,
            maximum_ram_bytes,
            DEVICE_CEILING,
        )?,
        (QmpCheckpointRamKind::Delta, Some(parent)) => QmpCheckpointCaptureRequest::delta(
            candidate,
            parent,
            ram_name,
            device_name,
            cancellation_name,
            maximum_ram_bytes,
            DEVICE_CEILING,
        )?,
        _ => return Err("capture kind and parent disagree".into()),
    };
    let report = qmp.capture_exact_checkpoint(&request)?;

    let complete_seals = SealFlags::SEAL | SealFlags::SHRINK | SealFlags::GROW | SealFlags::WRITE;
    fcntl_add_seals(&ram_file, complete_seals)?;
    fcntl_add_seals(&device_file, complete_seals)?;
    let ram_bytes = read_all(&mut ram_file)?;
    let device_bytes = read_all(&mut device_file)?;
    let ram_hash = sha256_hash(&ram_bytes);
    let device_hash = sha256_hash(&device_bytes);

    Ok(CapturedArtifact {
        report,
        ram_file,
        ram_bytes,
        ram_hash,
        device_file,
        device_bytes,
        device_hash,
    })
}

fn assert_exact_page_delta(
    artifact: &CapturedArtifact,
    expected_records: &[(u64, &[u8])],
    label: &str,
) -> Result<(), Box<dyn Error>> {
    let layer = parse_ram_layer(&artifact.ram_bytes)?;
    assert_eq!(layer.kind, QmpCheckpointRamKind::Delta);
    let observed_offsets: Vec<_> = layer.records.iter().map(|record| record.offset).collect();
    assert_eq!(
        layer.records.len(),
        expected_records.len(),
        "{label} delta record offsets: {observed_offsets:x?}"
    );

    for (record, (expected_offset, expected_bytes)) in layer.records.iter().zip(expected_records) {
        assert_eq!(record.offset, *expected_offset, "{label} record offset");
        assert_bytes_equal(
            &record.bytes,
            expected_bytes,
            &format!("{label} record bytes at 0x{expected_offset:x}"),
        );
    }
    Ok(())
}

fn assert_bytes_equal(observed: &[u8], expected: &[u8], context: &str) {
    assert_eq!(observed.len(), expected.len(), "{context}: byte length");

    let differing_offsets: Vec<_> = observed
        .iter()
        .zip(expected)
        .enumerate()
        .filter_map(|(offset, (observed, expected))| (observed != expected).then_some(offset))
        .collect();
    assert!(
        differing_offsets.is_empty(),
        "{context}: differing offsets {differing_offsets:x?}"
    );
}

fn resume_to_exact_boundary(
    qmp: &mut QemuQmpVmStateControlChannel<UnixStream>,
) -> Result<(), Box<dyn Error>> {
    qmp.resume_guest_acknowledged()?;
    wait_for_exact_boundary(qmp)
}

fn wait_for_exact_boundary(
    qmp: &mut QemuQmpVmStateControlChannel<UnixStream>,
) -> Result<(), Box<dyn Error>> {
    for _ in 0..EXACT_STOP_POLL_LIMIT {
        let state = qmp.client.query_status()?;
        if !state.running && state.status == QmpRunStateKind::Paused {
            return Ok(());
        }
        if !state.running || state.status != QmpRunStateKind::Running {
            return Err(format!("guest entered unexpected run state: {:?}", state.status).into());
        }
        thread::sleep(EXACT_STOP_POLL_INTERVAL);
    }

    Err("guest did not reach the next exact VMStop boundary".into())
}

fn measure_restore_to_runnable<const N: usize>(
    qmp: &mut QemuQmpVmStateControlChannel<UnixStream>,
    artifacts: [&CapturedArtifact; N],
    final_artifact: &CapturedArtifact,
    identity: QmpCheckpointIdentity,
) -> Result<Duration, Box<dyn Error>> {
    let started = monotonic_nanoseconds()?;
    restore(qmp, artifacts, final_artifact, identity)?;
    qmp.resume_guest_acknowledged()?;
    let elapsed = monotonic_nanoseconds()?
        .checked_sub(started)
        .ok_or("monotonic clock moved backwards during restore measurement")?;
    Ok(Duration::from_nanos(elapsed))
}

/// Reads a monotonic host clock solely for this external latency report.
fn monotonic_nanoseconds() -> Result<u64, Box<dyn Error>> {
    let now = clock_gettime(ClockId::Monotonic);
    let seconds = u64::try_from(now.tv_sec)?;
    let nanoseconds = u64::try_from(now.tv_nsec)?;

    seconds
        .checked_mul(1_000_000_000)
        .and_then(|total| total.checked_add(nanoseconds))
        .ok_or_else(|| "monotonic clock value exceeds u64 nanoseconds".into())
}

fn resume_until_page_changes(
    qmp: &mut QemuQmpVmStateControlChannel<UnixStream>,
    qtest: &mut QtestClient,
    address: u64,
    previous: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    for _ in 0..EXACT_STOP_POLL_LIMIT {
        resume_to_exact_boundary(qmp)?;
        let observed = qtest.read(address, previous.len())?;
        if observed != previous {
            return Ok(observed);
        }
    }

    Err("guest did not write the checkpoint delta target page".into())
}

fn restore<const N: usize>(
    qmp: &mut QemuQmpVmStateControlChannel<UnixStream>,
    artifacts: [&CapturedArtifact; N],
    final_artifact: &CapturedArtifact,
    identity: QmpCheckpointIdentity,
) -> Result<(), Box<dyn Error>> {
    let mut layers = Vec::with_capacity(N);
    for (index, artifact) in artifacts.iter().enumerate() {
        let name = QmpDescriptorName::new(format!("restore-ram-{index}"))?;
        qmp.install_exact_checkpoint_descriptor(&name, artifact.ram_file.as_fd())?;
        layers.push(QmpCheckpointRestoreLayer::new(
            name,
            artifact.ram_hash,
            artifact.ram_bytes.len() as u64,
        )?);
    }

    let device_name = QmpDescriptorName::new("restore-device")?;
    let cancellation_name = QmpDescriptorName::new("restore-cancel")?;
    let (cancellation, _cancellation_peer) = UnixStream::pair()?;
    qmp.install_exact_checkpoint_descriptor(&device_name, final_artifact.device_file.as_fd())?;
    qmp.install_exact_checkpoint_descriptor(&cancellation_name, cancellation.as_fd())?;
    let request = QmpCheckpointRestoreRequest::new(
        layers,
        device_name,
        final_artifact.device_hash,
        cancellation_name,
        identity,
        final_artifact.device_bytes.len() as u64,
    )?;
    let restored = qmp.restore_exact_checkpoint(&request)?;
    assert_eq!(restored.identity, identity);
    assert_eq!(restored.ram_layers, N as u64);
    Ok(())
}

fn reconstruct<'a>(
    artifacts: impl IntoIterator<Item = &'a CapturedArtifact>,
) -> Result<BTreeMap<String, Vec<u8>>, Box<dyn Error>> {
    let mut image: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for (layer_index, artifact) in artifacts.into_iter().enumerate() {
        let layer = parse_ram_layer(&artifact.ram_bytes)?;
        if layer_index == 0 && layer.kind != QmpCheckpointRamKind::Direct {
            return Err("checkpoint chain does not begin with a direct layer".into());
        }
        if layer_index != 0 && layer.kind != QmpCheckpointRamKind::Delta {
            return Err("checkpoint chain contains a non-delta child".into());
        }
        assert_eq!(layer.page_size as usize, PAGE_BYTES);

        for region in &layer.regions {
            match image.get(&region.name) {
                Some(bytes) if bytes.len() as u64 == region.length => {}
                Some(_) => return Err("RAM region length changed in checkpoint chain".into()),
                None if layer_index == 0 => {
                    image.insert(region.name.clone(), vec![0; region.length as usize]);
                }
                None => return Err("RAM region appeared after direct checkpoint".into()),
            }
        }
        for record in layer.records {
            let region = &layer.regions[record.region];
            let start = record.offset as usize;
            let end = start + record.bytes.len();
            image
                .get_mut(&region.name)
                .ok_or("RAM record names an absent region")?[start..end]
                .copy_from_slice(&record.bytes);
        }
    }
    Ok(image)
}

fn test_gpa() -> Result<u64, Box<dyn Error>> {
    let Some(value) = env::var_os(TEST_GPA_ENV) else {
        return Ok(DEFAULT_TEST_GPA);
    };
    let value = value.to_string_lossy();
    let value = value.strip_prefix("0x").unwrap_or(&value);
    Ok(u64::from_str_radix(value, 16)?)
}
