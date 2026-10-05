//! Bounded evidence for the complete native runtime-determinism trace.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::error::Error;
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, Write};

use crucible_qemu::{QemuRuntimeDeterminismTraceRecord, QemuRuntimeDeterminismTraceValidator};
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
    normalized_spool_bytes: u64,
    normalized_spool: RefCell<File>,
}

impl RuntimeTraceSummary {
    pub(super) fn report(&self) -> String {
        format!(
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
        )
    }
}

/// Validates every byte and row while retaining only bounded comparison data.
pub(super) fn summarize(
    reader: &mut dyn BufRead,
    raw_boundary: u64,
    virtual_boundary: i64,
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

    while read_bounded_line(reader, &mut line)? {
        bytes = bytes
            .checked_add(u64::try_from(line.len())?)
            .ok_or("runtime trace byte count overflowed")?;
        if u64::try_from(validator.rows())? >= MAXIMUM_ROWS {
            return Err("runtime trace row count exceeded its fixed ceiling".into());
        }
        raw_digest.update(&line);
        let row = std::str::from_utf8(&line[..line.len() - 1])?;
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
        normalized_spool_bytes,
        normalized_spool: RefCell::new(normalized_spool),
    })
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
}
