//! Differential kernel-evidence controls for bounded streaming line recognition.
// SPDX-License-Identifier: GPL-2.0-or-later

use std::sync::Mutex;

use super::*;
use crate::paged_ram::source::ObservationOperationError;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Event {
    Wait,
    Read {
        requested: usize,
        returned: Option<usize>,
    },
    Progress,
}

type Transcript = Arc<Mutex<Vec<Event>>>;

struct RecordedOperation {
    transcript: Transcript,
    waits: AtomicU64,
    fail_at: Option<u64>,
}

impl SourceOperation for RecordedOperation {
    fn wait_slice(&self) -> io::Result<std::time::Duration> {
        self.transcript.lock().unwrap().push(Event::Wait);
        if self.fail_at == Some(self.waits.fetch_add(1, Ordering::Relaxed)) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original operation expired",
            ));
        }
        Ok(std::time::Duration::from_millis(10))
    }

    fn complete(&self) -> io::Result<()> {
        Ok(())
    }

    fn wait_slice_for_observation(&self) -> Result<std::time::Duration, ObservationOperationError> {
        self.wait_slice().map_err(ObservationOperationError::Io)
    }

    fn complete_observation(&self) -> Result<(), ObservationOperationError> {
        Ok(())
    }
}

struct RecordedReader<'a> {
    remaining: &'a [u8],
    first_limit: usize,
    later_limit: usize,
    reads: usize,
    fail_at: Option<usize>,
    transcript: Transcript,
}

impl Read for RecordedReader<'_> {
    fn read(&mut self, destination: &mut [u8]) -> io::Result<usize> {
        let current = self.reads;
        self.reads += 1;
        if self.fail_at == Some(current) {
            self.transcript.lock().unwrap().push(Event::Read {
                requested: destination.len(),
                returned: None,
            });
            return Err(io::Error::from_raw_os_error(libc::EIO));
        }
        let limit = if current == 0 {
            self.first_limit
        } else {
            self.later_limit
        };
        let count = destination.len().min(limit).min(self.remaining.len());
        destination[..count].copy_from_slice(&self.remaining[..count]);
        self.remaining = &self.remaining[count..];
        self.transcript.lock().unwrap().push(Event::Read {
            requested: destination.len(),
            returned: Some(count),
        });
        Ok(count)
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Outcome {
    cause: Option<(String, String)>,
    transcript: Vec<Event>,
}

#[derive(Clone, Copy, Default)]
struct Failures {
    wait: Option<u64>,
    read: Option<usize>,
    progress: bool,
}

fn outcome(
    bytes: &[u8],
    spans: &[LockSpan],
    first_limit: usize,
    later_limit: usize,
    failures: Failures,
    predecessor: bool,
) -> Outcome {
    let transcript = Arc::new(Mutex::new(Vec::new()));
    let operation = RecordedOperation {
        transcript: Arc::clone(&transcript),
        waits: AtomicU64::new(0),
        fail_at: failures.wait,
    };
    let mut input = RecordedReader {
        remaining: bytes,
        first_limit,
        later_limit,
        reads: 0,
        fail_at: failures.read,
        transcript: Arc::clone(&transcript),
    };
    let mut progress = || {
        transcript.lock().unwrap().push(Event::Progress);
        if failures.progress {
            Err(RamError::Invariant("original progress refused"))
        } else {
            Ok(())
        }
    };
    let result = if predecessor {
        verify_reader_predecessor(&mut input, spans, true, &operation, &mut progress)
    } else {
        verify_reader(&mut input, spans, true, &operation, &mut progress)
    };
    let events = transcript.lock().unwrap().clone();
    Outcome {
        cause: result
            .err()
            .map(|error| (format!("{error:?}"), error.to_string())),
        transcript: events,
    }
}

fn compare(
    bytes: &[u8],
    spans: &[LockSpan],
    first_limit: usize,
    later_limit: usize,
    failures: Failures,
) -> Outcome {
    let candidate = outcome(bytes, spans, first_limit, later_limit, failures, false);
    let original = outcome(bytes, spans, first_limit, later_limit, failures, true);
    assert_eq!(candidate, original);
    assert!(
        candidate
            .transcript
            .iter()
            .filter_map(|event| match event {
                Event::Read { requested, .. } => Some(requested),
                _ => None,
            })
            .all(|size| *size == 8192)
    );
    candidate
}

#[test]
fn headers_flags_paths_and_non_utf8_match_at_every_read_boundary() {
    let span = [LockSpan {
        start: 0x2000,
        end: 0x4000,
    }];
    let fixtures: &[&[u8]] = &[
        b"1000-5000 arbitrary permissions and path\xff\nVmFlags: rd\tlo\rwr\n",
        b"0000000000001000-0000000000005000 anything\nVmFlags: lo\n",
        b"10000000000000000-5000 bad\nVmFlags: lo\n",
        b"1000-00000000000005000 bad\nVmFlags: lo\n",
        b"1000-5000\tmissing literal space\nVmFlags: lo\n",
        b"5000-1000 reversed\nVmFlags: lo\n",
        b"1000-5000 x\nVmFlags: lol loz ol lo\n",
        b"1000-5000 x\nVmFlags: lol loz ol\n",
        b"1000-5000 x\nVmFlags: lo\nVmFlags: lo\n",
        b"1000-5000 x\nVmFlags: lo",
        b"\nIgnored: 1000-5000 x\nVmFlags: lo\n",
    ];
    for bytes in fixtures {
        for boundary in 1..=bytes.len() {
            compare(bytes, &span, boundary, 8192, Failures::default());
            compare(bytes, &span, boundary, 1, Failures::default());
        }
    }
    let successful = compare(fixtures[0], &span, 8192, 8192, Failures::default());
    assert!(successful.cause.is_none());
    assert!(
        compare(fixtures[7], &span, 8192, 8192, Failures::default())
            .cause
            .is_some()
    );
}

#[test]
fn line_limit_truncation_and_first_cause_remain_at_original_position() {
    for prefix in [
        b"Ignored: ".as_slice(),
        b"VmFlags: ".as_slice(),
        b"1000-5000 ".as_slice(),
        b"malformed- ".as_slice(),
    ] {
        for length in [8192, 8193] {
            let mut bytes = prefix.to_vec();
            bytes.resize(length, b'x');
            bytes.push(b'\n');
            for limit in [1, 31, 8192] {
                let observed = compare(&bytes, &[], limit, limit, Failures::default());
                assert_eq!(observed.cause.is_some(), length == 8193);
            }
            bytes.pop();
            let observed = compare(&bytes, &[], 8192, 8192, Failures::default());
            let message = observed.cause.unwrap().1;
            assert!(message.contains(if length == 8192 {
                "truncated kernel VMA evidence"
            } else {
                "line exceeds bound"
            }));
        }
    }
}

#[test]
fn cancellation_read_and_progress_refusal_preserve_exact_transcript() {
    let bytes = b"1000-3000 x\nVmFlags: lo\n3000-5000 x\nVmFlags: lo\n";
    let span = [LockSpan {
        start: 0x2000,
        end: 0x4000,
    }];
    let normal = compare(bytes, &span, 7, 7, Failures::default());
    assert!(normal.cause.is_none());
    let waits = normal
        .transcript
        .iter()
        .filter(|event| **event == Event::Wait)
        .count();
    for failure in 0..waits {
        let observed = compare(
            bytes,
            &span,
            7,
            7,
            Failures {
                wait: Some(failure as u64),
                ..Failures::default()
            },
        );
        assert!(
            observed
                .cause
                .unwrap()
                .1
                .contains("original operation expired")
        );
    }
    let reads = normal
        .transcript
        .iter()
        .filter(|event| matches!(event, Event::Read { .. }))
        .count();
    for failure in 0..reads {
        assert!(
            compare(
                bytes,
                &span,
                7,
                7,
                Failures {
                    read: Some(failure),
                    ..Failures::default()
                }
            )
            .cause
            .is_some()
        );
    }
    let failed = compare(
        bytes,
        &span,
        7,
        7,
        Failures {
            progress: true,
            ..Failures::default()
        },
    );
    assert!(
        failed
            .cause
            .unwrap()
            .1
            .contains("original progress refused")
    );
}

#[test]
fn actual_procfs_evidence_matches_original_without_a_second_line_buffer() {
    let mut file = File::open("/proc/self/smaps").unwrap();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    assert!(!bytes.is_empty());
    let captured = compare(&bytes, &[], 8192, 8192, Failures::default());
    assert!(captured.cause.is_none());

    // Read actual procfs directly too; no guest memory or pager is activated.
    let operation = RecordedOperation {
        transcript: Arc::new(Mutex::new(Vec::new())),
        waits: AtomicU64::new(0),
        fail_at: None,
    };
    verify_reader(
        &mut File::open("/proc/self/smaps").unwrap(),
        &[],
        false,
        &operation,
        &mut || Ok(()),
    )
    .unwrap();
}

fn verify_reader_predecessor(
    input: &mut impl Read,
    spans: &[LockSpan],
    locked: bool,
    operation: &dyn SourceOperation,
    progress: &mut impl FnMut() -> Result<(), RamError>,
) -> Result<(), RamError> {
    let mut buffer = [0_u8; 8192];
    let mut begin = 0;
    let mut end = 0;
    let mut line = [0_u8; 8192];
    let mut length = 0;
    let mut mapping = None;
    let mut flags = None;
    let mut index = 0;
    let mut covered = spans.first().map_or(0, |span| span.start);
    loop {
        if begin == end {
            operation.wait_slice()?;
            end = input.read(&mut buffer)?;
            operation.wait_slice()?;
            begin = 0;
            if end == 0 {
                if length != 0 {
                    return Err(RamError::Invariant("truncated kernel VMA evidence"));
                }
                let previous = (index, covered);
                verify_mapping(mapping, flags, spans, locked, &mut index, &mut covered)?;
                if previous != (index, covered) {
                    progress()?;
                }
                break;
            }
        }
        let byte = buffer[begin];
        begin += 1;
        if byte != b'\n' {
            let destination = line
                .get_mut(length)
                .ok_or("kernel VMA evidence line exceeds bound")?;
            *destination = byte;
            length += 1;
            continue;
        }
        let value = &line[..length];
        if let Some(next) = mapping_header(value) {
            operation.wait_slice()?;
            let previous = (index, covered);
            verify_mapping(mapping, flags, spans, locked, &mut index, &mut covered)?;
            if previous != (index, covered) {
                progress()?;
            }
            mapping = Some(next);
            flags = None;
        } else if let Some(value) = value.strip_prefix(b"VmFlags:") {
            if flags.is_some() {
                return Err(RamError::Invariant("duplicate kernel VMA flags"));
            }
            flags = Some(
                value
                    .split(|byte| byte.is_ascii_whitespace())
                    .any(|word| word == b"lo"),
            );
        }
        length = 0;
    }
    if index != spans.len() {
        return Err(RamError::Invariant(
            "guest mapping lock coverage is incomplete",
        ));
    }
    Ok(())
}
