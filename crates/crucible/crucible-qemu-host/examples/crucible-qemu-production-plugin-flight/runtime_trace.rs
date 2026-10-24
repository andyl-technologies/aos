//! Bounded evidence for the complete native runtime-determinism trace.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::error::Error;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, Write};

use crucible_qemu_host::{QemuRuntimeDeterminismTraceRecord, QemuRuntimeDeterminismTraceValidator};
use sha2::{Digest, Sha256};

const MAXIMUM_ROW_BYTES: usize = 4096;
const MAXIMUM_ROWS: u64 = 4_000_000;
const CONTEXT_ROWS: usize = 16;
const CONTEXT_RADIUS: usize = 8;
const MAXIMUM_NORMALIZED_SPOOL_BYTES: u64 = 256 * 1024 * 1024;

/// Full-file digest and bounded localization for one validated trace.
#[derive(Debug)]
pub(super) struct RuntimeTraceSummary {
    pub(super) bytes: u64,
    pub(super) rows: u64,
    pub(super) raw_sha256: String,
    pub(super) post_boundary_rows: u64,
    pub(super) post_boundary_sha256: String,
    pub(super) prefix: Vec<QemuRuntimeDeterminismTraceRecord>,
    pub(super) tail: VecDeque<QemuRuntimeDeterminismTraceRecord>,
    origin_header: Option<(u64, bool, u64)>,
    origin_rows: u64,
    normalized_spool_bytes: u64,
    normalized_spool: RefCell<File>,
}

impl RuntimeTraceSummary {
    /// Rejects missing, incomplete, or truncated APIC diagnostic data.
    pub(super) fn validate_origin_diagnostic(&self) -> Result<(), Box<dyn Error>> {
        match self.origin_header {
            Some((rows, false, 0)) if rows != 0 && rows == self.origin_rows => Ok(()),
            _ => Err("APIC origin diagnostic is absent, incomplete, or overflowed".into()),
        }
    }

    pub(super) fn report(&self) -> String {
        let mut report = format!(
            "schema=crucible-runtime-trace-summary-v1\n\
             bytes={}\nrows={}\nraw_sha256={}\n\
             post_8m_rows={}\npost_8m_normalized_sha256={}\n\
             post_8m_first={:?}\npost_8m_tail={:?}\n",
            self.bytes,
            self.rows,
            self.raw_sha256,
            self.post_boundary_rows,
            self.post_boundary_sha256,
            self.prefix,
            self.tail,
        );
        if let Some(header) = self.origin_header {
            report.push_str(&format!(
                "apic_origin_header={header:?}\napic_origin_rows={}\n",
                self.origin_rows
            ));
        }
        report
    }
}

/// Validates every byte and row while retaining only bounded comparison data.
pub(super) fn summarize(
    reader: &mut dyn BufRead,
    raw_boundary: u64,
    virtual_boundary: i64,
) -> Result<RuntimeTraceSummary, Box<dyn Error>> {
    summarize_impl(reader, raw_boundary, virtual_boundary, false)
}

fn summarize_impl(
    reader: &mut dyn BufRead,
    raw_boundary: u64,
    virtual_boundary: i64,
    origin_diagnostic: bool,
) -> Result<RuntimeTraceSummary, Box<dyn Error>> {
    let mut validator = QemuRuntimeDeterminismTraceValidator::default();
    let mut raw_digest = Sha256::new();
    let mut normalized_digest = Sha256::new();
    let mut bytes = 0_u64;
    let mut post_boundary_rows = 0_u64;
    let mut prefix = Vec::with_capacity(CONTEXT_ROWS);
    let mut tail = VecDeque::with_capacity(CONTEXT_ROWS);
    // The anonymous spool keeps full normalized rows off the heap and vanishes
    // on drop. Re-reading it after both variants localizes a hash mismatch.
    let mut normalized_spool = tempfile::tempfile()?;
    let mut normalized_spool_bytes = 0_u64;
    let mut line = Vec::with_capacity(256);
    let mut origin_header = None;
    let mut origin_rows = 0_u64;
    // At most one split row is pending; only its complete ordered join counts.
    let mut origin_pending = None;

    while read_bounded_line(reader, &mut line)? {
        bytes = bytes
            .checked_add(u64::try_from(line.len())?)
            .ok_or("runtime trace byte count overflowed")?;
        if u64::try_from(validator.rows())? >= MAXIMUM_ROWS {
            return Err("runtime trace row count exceeded its fixed ceiling".into());
        }
        raw_digest.update(&line);
        let row = std::str::from_utf8(&line[..line.len() - 1])?;
        if origin_diagnostic && row.starts_with("crucible_apic_origin_") {
            observe_origin_row(
                row,
                &mut origin_header,
                &mut origin_rows,
                &mut origin_pending,
            )?;
            continue;
        }
        let record = validator.push_row(row)?;
        let virtual_ps = match record {
            QemuRuntimeDeterminismTraceRecord::Idle(idle) => idle.virtual_ps,
            QemuRuntimeDeterminismTraceRecord::Timer(timer) => timer.current_ps,
        };
        if record.raw_icount() < raw_boundary || virtual_ps < virtual_boundary {
            continue;
        }

        post_boundary_rows += 1;
        let normalized = record.normalized_canonical_row();
        normalized_spool_bytes = normalized_spool_bytes
            .checked_add(u64::try_from(normalized.len() + 1)?)
            .ok_or("normalized runtime trace spool byte count overflowed")?;
        if normalized_spool_bytes > MAXIMUM_NORMALIZED_SPOOL_BYTES {
            return Err("normalized runtime trace spool exceeded its fixed byte ceiling".into());
        }
        normalized_spool.write_all(normalized.as_bytes())?;
        normalized_spool.write_all(b"\n")?;
        normalized_digest.update(normalized.as_bytes());
        normalized_digest.update(b"\n");
        if prefix.len() < CONTEXT_ROWS {
            prefix.push(record);
        }
        if tail.len() == CONTEXT_ROWS {
            tail.pop_front();
        }
        tail.push_back(record);
    }
    if origin_pending.is_some() {
        return Err("incomplete APIC origin row".into());
    }
    validator.finish()?;
    if post_boundary_rows == 0 {
        return Err("post-8M native runtime trace is empty".into());
    }
    normalized_spool.flush()?;
    if normalized_spool.metadata()?.len() != normalized_spool_bytes {
        return Err("normalized runtime trace spool length changed during validation".into());
    }

    Ok(RuntimeTraceSummary {
        bytes,
        rows: u64::try_from(validator.rows())?,
        raw_sha256: format!("{:x}", raw_digest.finalize()),
        post_boundary_rows,
        post_boundary_sha256: format!("{:x}", normalized_digest.finalize()),
        prefix,
        tail,
        origin_header,
        origin_rows,
        normalized_spool_bytes,
        normalized_spool: RefCell::new(normalized_spool),
    })
}

/// Retains complete raw bytes before parsing or invoking any comparison.
///
/// The caller supplies a newly created, preowned file. Overflow leaves the
/// measured prefix present and returns an error; it never admits a short trace.
pub(super) fn retain_and_summarize(
    reader: &mut dyn BufRead,
    output: &mut File,
    raw_boundary: u64,
    virtual_boundary: i64,
) -> Result<RuntimeTraceSummary, Box<dyn Error>> {
    let copied = std::io::copy(&mut reader.take(MAXIMUM_NORMALIZED_SPOOL_BYTES + 1), output)?;
    output.flush()?;
    if copied > MAXIMUM_NORMALIZED_SPOOL_BYTES {
        return Err("raw runtime trace retention exceeded its fixed byte ceiling".into());
    }
    if output.metadata()?.len() != copied {
        return Err("raw runtime trace retention length changed".into());
    }
    output.rewind()?;
    summarize_impl(
        &mut BufReader::new(output),
        raw_boundary,
        virtual_boundary,
        true,
    )
}

fn observe_origin_row(
    row: &str,
    header: &mut Option<(u64, bool, u64)>,
    rows: &mut u64,
    pending: &mut Option<(u64, u8)>,
) -> Result<(), Box<dyn Error>> {
    let fields = row.split(' ').collect::<Vec<_>>();
    if fields.first() == Some(&"crucible_apic_origin_header") {
        if header.is_some() || pending.is_some() || fields.len() != 4 {
            return Err("invalid APIC origin header".into());
        }
        let value = |index: usize, name: &str| -> Result<u64, Box<dyn Error>> {
            let text = fields[index]
                .strip_prefix(name)
                .ok_or("invalid APIC origin field")?;
            let parsed: u64 = text.parse()?;
            if parsed.to_string() != text {
                return Err("noncanonical APIC origin header field".into());
            }
            Ok(parsed)
        };
        let count = value(1, "rows=")?;
        let overflow = value(2, "overflow=")?;
        let incomplete = value(3, "incomplete=")?;
        if count > 65_536 || overflow > 1 || incomplete > count {
            return Err("invalid APIC origin geometry".into());
        }
        *header = Some((count, overflow != 0, incomplete));
        return Ok(());
    }

    // QEMU's genuine tracetool permits ten arguments per event. Each payload
    // stays below that bound; the parser authenticates order and ordinal join.
    let (part, names): (u8, &[&str]) = match fields.first().copied() {
        Some("crucible_apic_origin_identity") => (
            1,
            &[
                "seq", "phase", "timer", "cpu", "apic", "writer", "pc", "raw",
            ],
        ),
        Some("crucible_apic_origin_clock") => (
            2,
            &[
                "seq",
                "origin_lo",
                "origin_hi",
                "now_lo",
                "now_hi",
                "deadline_lo",
                "deadline_hi",
            ],
        ),
        Some("crucible_apic_origin_program") => (
            3,
            &[
                "seq",
                "reg",
                "value",
                "count",
                "divide",
                "shift",
                "lvt",
                "arm",
                "fault_arm",
            ],
        ),
        _ => return Err("unknown APIC origin diagnostic event".into()),
    };
    if header.is_none() || fields.len() != names.len() + 1 {
        return Err("invalid APIC origin row part".into());
    }
    for (field, name) in fields[1..].iter().zip(names.iter().copied()) {
        let (actual, value) = field.split_once('=').ok_or("invalid APIC origin field")?;
        let parsed: u64 = value.parse()?;
        if actual != name || parsed.to_string() != value {
            return Err("noncanonical APIC origin field".into());
        }
        let invalid_extent = match name {
            "phase" => !(1..=5).contains(&parsed),
            "cpu" => parsed >= 4_096,
            "seq" | "apic" | "writer" | "reg" | "value" | "count" | "divide" | "shift" | "lvt" => {
                parsed > u64::from(u32::MAX)
            }
            _ => false,
        };
        if invalid_extent {
            return Err("APIC origin field exceeded its native extent".into());
        }
    }
    let sequence: u64 = fields[1]
        .strip_prefix("seq=")
        .ok_or("missing APIC origin sequence")?
        .parse()?;
    if sequence != *rows + 1 || *rows == 65_536 {
        return Err("noncontiguous APIC origin row".into());
    }
    let expected = (*pending).unwrap_or((sequence, 1));
    if (sequence, part) != expected {
        return Err("APIC origin row part changed ordinal or order".into());
    }
    if part == 3 {
        *pending = None;
        *rows += 1;
    } else {
        *pending = Some((sequence, part + 1));
    }
    Ok(())
}

/// Revalidates both anonymous spools and locates the first different row.
pub(super) fn compare(
    reference_name: &str,
    reference: &RuntimeTraceSummary,
    candidate_name: &str,
    candidate: &RuntimeTraceSummary,
) -> Result<String, Box<dyn Error>> {
    let mut reference_spool = reference.normalized_spool.try_borrow_mut()?;
    let mut candidate_spool = candidate.normalized_spool.try_borrow_mut()?;
    if reference_spool.metadata()?.len() != reference.normalized_spool_bytes
        || candidate_spool.metadata()?.len() != candidate.normalized_spool_bytes
    {
        return Err("normalized runtime trace spool length changed before comparison".into());
    }
    reference_spool.rewind()?;
    candidate_spool.rewind()?;

    let mut reference_reader = BufReader::new(&mut *reference_spool);
    let mut candidate_reader = BufReader::new(&mut *candidate_spool);
    let mut reference_digest = Sha256::new();
    let mut candidate_digest = Sha256::new();
    let mut reference_rows = 0_u64;
    let mut candidate_rows = 0_u64;
    let mut preceding = VecDeque::with_capacity(CONTEXT_RADIUS);
    let mut first_difference = None;
    let mut following = Vec::with_capacity(CONTEXT_RADIUS);
    let mut reference_line = Vec::new();
    let mut candidate_line = Vec::new();

    loop {
        let reference_present = read_bounded_line(&mut reference_reader, &mut reference_line)?;
        let candidate_present = read_bounded_line(&mut candidate_reader, &mut candidate_line)?;
        if !reference_present && !candidate_present {
            break;
        }
        if reference_present {
            reference_digest.update(&reference_line);
            reference_rows += 1;
        }
        if candidate_present {
            candidate_digest.update(&candidate_line);
            candidate_rows += 1;
        }

        let row_index = reference_rows.max(candidate_rows) - 1;
        let pair = (
            normalized_row_context(&reference_line, reference_present)?,
            normalized_row_context(&candidate_line, candidate_present)?,
        );
        if first_difference.is_none() {
            if reference_line != candidate_line || reference_present != candidate_present {
                first_difference = Some((row_index, preceding.clone(), pair));
            } else {
                if preceding.len() == CONTEXT_RADIUS {
                    preceding.pop_front();
                }
                preceding.push_back(pair);
            }
        } else if following.len() < CONTEXT_RADIUS {
            following.push(pair);
        }
    }

    if reference_rows != reference.post_boundary_rows
        || candidate_rows != candidate.post_boundary_rows
        || format!("{:x}", reference_digest.finalize()) != reference.post_boundary_sha256
        || format!("{:x}", candidate_digest.finalize()) != candidate.post_boundary_sha256
        || reference_spool.metadata()?.len() != reference.normalized_spool_bytes
        || candidate_spool.metadata()?.len() != candidate.normalized_spool_bytes
    {
        return Err(
            "normalized runtime trace spool failed digest, count, or size verification".into(),
        );
    }

    if let Some((index, preceding, differing)) = first_difference {
        return Ok(format!(
            "first_split={reference_name}/{candidate_name} index={index} \
             reference_rows={} candidate_rows={} reference_sha256={} candidate_sha256={} \
             preceding={preceding:?} differing={differing:?} following={following:?}",
            reference.post_boundary_rows,
            candidate.post_boundary_rows,
            reference.post_boundary_sha256,
            candidate.post_boundary_sha256,
        ));
    }
    Ok(format!(
        "post_8m_native_sequences_identical=true rows={} sha256={}",
        reference.post_boundary_rows, reference.post_boundary_sha256,
    ))
}

fn normalized_row_context(line: &[u8], present: bool) -> Result<String, Box<dyn Error>> {
    if !present {
        return Ok(String::from("<end-of-trace>"));
    }
    Ok(String::from_utf8(line[..line.len() - 1].to_vec())?)
}

fn read_bounded_line(reader: &mut dyn BufRead, line: &mut Vec<u8>) -> Result<bool, Box<dyn Error>> {
    line.clear();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            if line.is_empty() {
                return Ok(false);
            }
            return Err("runtime-determinism trace does not end with LF".into());
        }
        let complete = available.iter().position(|byte| *byte == b'\n');
        let consumed = complete.map_or(available.len(), |index| index + 1);
        if line.len() + consumed > MAXIMUM_ROW_BYTES {
            return Err("runtime trace row exceeded its fixed byte ceiling".into());
        }
        line.extend_from_slice(&available[..consumed]);
        reader.consume(consumed);
        if complete.is_some() {
            return Ok(true);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Seek, Write};

    use super::{compare, summarize};

    const TRACE: &str = "crucible_sim_determinism_idle phase=request seq=1 raw=160000 virtual_ps=8000000 target_tick=9000000 deadline_ps=-1 rr_owner=0 rr_cursor=1 cpu_count=4 halted=0xf work=0x0 exit=0x0 interrupt=0x0 stop=0x0 state=2\n\
        crucible_sim_determinism_idle phase=complete seq=2 raw=160000 virtual_ps=9000000 target_tick=9000000 deadline_ps=-1 rr_owner=0 rr_cursor=1 cpu_count=4 halted=0xf work=0x0 exit=0x0 interrupt=0x0 stop=0x0 state=2\n";

    #[test]
    fn comparison_rechecks_the_anonymous_spool_before_reporting_identity() {
        let reference = summarize(&mut Cursor::new(TRACE), 160_000, 8_000_000)
            .expect("reference trace should validate");
        let candidate = summarize(&mut Cursor::new(TRACE), 160_000, 8_000_000)
            .expect("candidate trace should validate");
        assert!(
            compare("reference", &reference, "candidate", &candidate)
                .expect("untouched spools should compare")
                .contains("post_8m_native_sequences_identical=true")
        );

        let mut spool = candidate.normalized_spool.borrow_mut();
        spool.rewind().expect("anonymous spool should rewind");
        spool
            .write_all(b"x")
            .expect("test should alter the anonymous spool");
        drop(spool);

        let error = compare("reference", &reference, "candidate", &candidate)
            .expect_err("tampered spool must fail closed");
        assert!(
            error
                .to_string()
                .contains("digest, count, or size verification")
        );
    }

    #[test]
    fn full_raw_diagnostic_is_retained_before_exact_timer_comparison()
    -> Result<(), Box<dyn std::error::Error>> {
        use sha2::{Digest, Sha256};
        use std::io::Read;

        let diagnostic = "crucible_apic_origin_header rows=1 overflow=0 incomplete=0\n\
            crucible_apic_origin_identity seq=1 phase=3 timer=5 cpu=1 apic=1 writer=1 pc=4096 raw=160000\n\
            crucible_apic_origin_clock seq=1 origin_lo=8000000 origin_hi=0 now_lo=8000000 now_hi=0 deadline_lo=9000000 deadline_hi=0\n\
            crucible_apic_origin_program seq=1 reg=56 value=17 count=17 divide=0 shift=1 lvt=131104 arm=1 fault_arm=0\n";
        let raw = format!("{TRACE}{diagnostic}");
        let mut retained = tempfile::tempfile()?;
        let observed =
            super::retain_and_summarize(&mut Cursor::new(&raw), &mut retained, 160_000, 8_000_000)?;
        observed.validate_origin_diagnostic()?;
        retained.rewind()?;
        let mut copied = String::new();
        retained.read_to_string(&mut copied)?;
        assert_eq!(copied, raw);
        assert_eq!(
            observed.raw_sha256,
            format!("{:x}", Sha256::digest(raw.as_bytes()))
        );
        let original = summarize(&mut Cursor::new(TRACE), 160_000, 8_000_000)?;
        assert!(
            compare("original", &original, "diagnostic", &observed)?
                .contains("post_8m_native_sequences_identical=true")
        );
        assert!(summarize(&mut Cursor::new(&raw), 160_000, 8_000_000).is_err());
        Ok(())
    }

    #[test]
    fn overflow_and_missing_origin_remain_visible_without_weakening_the_original_parser()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::io::Read;

        for diagnostic in [
            "",
            "crucible_apic_origin_header rows=0 overflow=1 incomplete=0\n",
        ] {
            let raw = format!("{TRACE}{diagnostic}");
            let mut retained = tempfile::tempfile()?;
            let observed = super::retain_and_summarize(
                &mut Cursor::new(&raw),
                &mut retained,
                160_000,
                8_000_000,
            )?;
            assert!(observed.validate_origin_diagnostic().is_err());
            retained.rewind()?;
            let mut copied = String::new();
            retained.read_to_string(&mut copied)?;
            assert_eq!(copied, raw);
        }
        Ok(())
    }

    #[test]
    fn malformed_origin_does_not_discard_the_retained_raw_file()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::io::Read;

        let header = "crucible_apic_origin_header rows=1 overflow=0 incomplete=0\n";
        let identity = "crucible_apic_origin_identity seq=1 phase=3 timer=5 cpu=1 apic=1 writer=1 pc=4096 raw=160000\n";
        let clock = "crucible_apic_origin_clock seq=1 origin_lo=8000000 origin_hi=0 now_lo=8000000 now_hi=0 deadline_lo=9000000 deadline_hi=0\n";
        let program = "crucible_apic_origin_program seq=1 reg=56 value=17 count=17 divide=0 shift=1 lvt=131104 arm=1 fault_arm=0\n";
        let foreign_clock = clock.replace("seq=1", "seq=2");
        let foreign_native = identity.replace("phase=3", "phase=6");
        let invalid = [
            format!("{header}crucible_apic_origin_row seq=2 foreign=1\n"),
            format!("{header}{identity}{clock}"),
            format!("{header}{identity}{foreign_clock}{program}"),
            format!("{header}{clock}{identity}{program}"),
            format!("{header}{identity}{identity}{clock}{program}"),
            format!("{header}{identity}{header}{clock}{program}"),
            format!("{header}{foreign_native}{clock}{program}"),
        ];
        for diagnostic in invalid {
            let raw = format!("{TRACE}{diagnostic}");
            let mut retained = tempfile::tempfile()?;
            assert!(
                super::retain_and_summarize(
                    &mut Cursor::new(&raw),
                    &mut retained,
                    160_000,
                    8_000_000
                )
                .is_err()
            );
            retained.rewind()?;
            let mut copied = String::new();
            retained.read_to_string(&mut copied)?;
            assert_eq!(copied, raw);
        }
        Ok(())
    }

    #[test]
    fn four_retirements_and_two_hundred_picoseconds_still_localize_an_exact_split()
    -> Result<(), Box<dyn std::error::Error>> {
        let reference = "crucible_sim_determinism_timer seq=1 timer=5 list=6 scope=global owner=rr expire_ps=268877553450 current_ps=268877553450 raw=5377551068\n";
        let hostile = "crucible_sim_determinism_timer seq=1 timer=5 list=6 scope=global owner=rr expire_ps=268877553650 current_ps=268877553650 raw=5377551072\n";
        let reference = summarize(&mut Cursor::new(reference), 0, 0)?;
        let hostile = summarize(&mut Cursor::new(hostile), 0, 0)?;
        let result = compare("reference", &reference, "hostile", &hostile)?;
        assert!(result.contains("first_split=reference/hostile index=0"));
        assert!(result.contains("268877553450") && result.contains("268877553650"));
        assert!(result.contains("5377551068") && result.contains("5377551072"));
        Ok(())
    }
}
