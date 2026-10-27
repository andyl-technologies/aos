//! Bounded-memory external sort of fixed-width sorted-file records.
//!
//! A repack names replacement packs by content-derived [`super::PackId`]s
//! that arrive in logical-ID order, not pack-ID order. The sorter keeps at
//! most [`RUN_RECORDS`] records resident, spills sorted runs to unnamed
//! temporary files in the administrative directory, merges at most
//! [`MAX_MERGE_FAN_IN`] runs at a time, and streams the final merge. Unnamed
//! files vanish with the process, so an interrupted sort leaves nothing to
//! reclaim.

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use super::StoreError;
use super::sorted_file::SortedRecord;

/// Records held in memory before one sorted run is spilled.
const RUN_RECORDS: usize = 65_536;

/// Maximum runs read concurrently by one merge.
const MAX_MERGE_FAN_IN: usize = 64;

/// Buffered capacity of each run reader and writer.
const RUN_BUFFER_BYTES: usize = 64 * 1024;

/// Accumulates records and yields them in key order.
pub(super) struct ExternalSorter<R: SortedRecord> {
    directory: PathBuf,
    run_records: usize,
    buffer: Vec<R>,
    runs: Vec<File>,
}

impl<R: SortedRecord> ExternalSorter<R> {
    /// Creates a sorter that spills runs into `directory`.
    pub(super) fn new(directory: &Path) -> Self {
        Self {
            directory: directory.to_path_buf(),
            run_records: RUN_RECORDS,
            buffer: Vec::new(),
            runs: Vec::new(),
        }
    }

    /// Creates a sorter with an explicit resident run size.
    #[cfg(test)]
    pub(super) fn with_run_records(directory: &Path, run_records: usize) -> Self {
        Self {
            directory: directory.to_path_buf(),
            run_records: run_records.max(1),
            buffer: Vec::new(),
            runs: Vec::new(),
        }
    }

    /// Adds one record.
    pub(super) fn push(&mut self, record: R) -> Result<(), StoreError> {
        self.buffer.push(record);
        if self.buffer.len() >= self.run_records {
            self.spill()?;
        }
        Ok(())
    }

    /// Returns every pushed record in nondecreasing key order.
    pub(super) fn finish(mut self) -> Result<SortedRecords<R>, StoreError> {
        if self.runs.is_empty() {
            self.buffer.sort_unstable_by_key(R::key);
            return Ok(SortedRecords::Memory(
                std::mem::take(&mut self.buffer).into_iter(),
            ));
        }

        if !self.buffer.is_empty() {
            self.spill()?;
        }
        let mut runs = std::mem::take(&mut self.runs);
        while runs.len() > MAX_MERGE_FAN_IN {
            let mut merged = Vec::with_capacity(runs.len().div_ceil(MAX_MERGE_FAN_IN));
            let mut remaining = runs.into_iter();
            loop {
                let group = remaining
                    .by_ref()
                    .take(MAX_MERGE_FAN_IN)
                    .collect::<Vec<_>>();
                if group.is_empty() {
                    break;
                }
                let mut output = RunWriter::<R>::create(&self.directory)?;
                for record in RunMerger::new(group)? {
                    output.push(record?)?;
                }
                merged.push(output.finish()?);
            }
            runs = merged;
        }
        Ok(SortedRecords::Runs(RunMerger::new(runs)?))
    }

    fn spill(&mut self) -> Result<(), StoreError> {
        self.buffer.sort_unstable_by_key(R::key);
        let mut output = RunWriter::<R>::create(&self.directory)?;
        for record in self.buffer.drain(..) {
            output.push(record)?;
        }
        self.runs.push(output.finish()?);
        Ok(())
    }
}

/// Sorted output of an [`ExternalSorter`].
pub(super) enum SortedRecords<R: SortedRecord> {
    /// Every record fit in one resident run.
    Memory(std::vec::IntoIter<R>),
    /// Streaming merge of spilled runs.
    Runs(RunMerger<R>),
}

impl<R: SortedRecord> Iterator for SortedRecords<R> {
    type Item = Result<R, StoreError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Memory(records) => records.next().map(Ok),
            Self::Runs(merger) => merger.next(),
        }
    }
}

struct RunWriter<R> {
    output: BufWriter<File>,
    encoded: Vec<u8>,
    _record: std::marker::PhantomData<R>,
}

impl<R: SortedRecord> RunWriter<R> {
    fn create(directory: &Path) -> Result<Self, StoreError> {
        let file = tempfile::tempfile_in(directory).map_err(|source| StoreError::Io {
            operation: "create packed sort run",
            path: directory.to_path_buf(),
            source,
        })?;
        Ok(Self {
            output: BufWriter::with_capacity(RUN_BUFFER_BYTES, file),
            encoded: vec![0; R::FORMAT.record_width],
            _record: std::marker::PhantomData,
        })
    }

    fn push(&mut self, record: R) -> Result<(), StoreError> {
        record.encode(&mut self.encoded);
        self.output
            .write_all(&self.encoded)
            .map_err(|source| run_error("write packed sort run", source))
    }

    fn finish(self) -> Result<File, StoreError> {
        let mut file = self
            .output
            .into_inner()
            .map_err(|error| run_error("flush packed sort run", error.into_error()))?;
        file.seek(SeekFrom::Start(0))
            .map_err(|source| run_error("rewind packed sort run", source))?;
        Ok(file)
    }
}

/// K-way merge of sorted runs.
pub(super) struct RunMerger<R: SortedRecord> {
    readers: Vec<BufReader<File>>,
    heads: Vec<Option<R>>,
    heap: BinaryHeap<Reverse<(R::Key, usize)>>,
    encoded: Vec<u8>,
    failed: bool,
}

impl<R: SortedRecord> RunMerger<R> {
    fn new(runs: Vec<File>) -> Result<Self, StoreError> {
        let mut merger = Self {
            readers: runs
                .into_iter()
                .map(|run| BufReader::with_capacity(RUN_BUFFER_BYTES, run))
                .collect(),
            heads: Vec::new(),
            heap: BinaryHeap::new(),
            encoded: vec![0; R::FORMAT.record_width],
            failed: false,
        };
        merger.heads = vec![None; merger.readers.len()];
        for run in 0..merger.readers.len() {
            merger.advance(run)?;
        }
        Ok(merger)
    }

    fn advance(&mut self, run: usize) -> Result<(), StoreError> {
        match self.readers[run].read_exact(&mut self.encoded) {
            Ok(()) => {
                let record = R::decode(&self.encoded)?;
                self.heap.push(Reverse((record.key(), run)));
                self.heads[run] = Some(record);
                Ok(())
            }
            Err(source) if source.kind() == std::io::ErrorKind::UnexpectedEof => {
                self.heads[run] = None;
                Ok(())
            }
            Err(source) => Err(run_error("read packed sort run", source)),
        }
    }

    fn next_record(&mut self) -> Result<Option<R>, StoreError> {
        let Some(Reverse((_key, run))) = self.heap.pop() else {
            return Ok(None);
        };
        let record = self.heads[run].take().ok_or(StoreError::Incompatible)?;
        self.advance(run)?;
        Ok(Some(record))
    }
}

impl<R: SortedRecord> Iterator for RunMerger<R> {
    type Item = Result<R, StoreError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        let result = self.next_record().transpose();
        if matches!(result, Some(Err(_))) {
            self.failed = true;
        }
        result
    }
}

fn run_error(operation: &'static str, source: std::io::Error) -> StoreError {
    StoreError::StreamIo { operation, source }
}
