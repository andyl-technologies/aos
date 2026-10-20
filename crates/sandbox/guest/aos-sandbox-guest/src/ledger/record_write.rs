//! Shares protected record serialization with retained timeout write prefixes.
//!
//! Ordinary creation closes its File at the original return boundary. Selected
//! replacement retains both files and all actual errors until rename and the
//! containing-directory sync complete. A failed prefix cannot be replayed.

use super::*;

trait RecordWriter {
    fn open(&mut self, path: &Path) -> std::io::Result<()>;
    fn encode<T: Serialize>(&mut self, record: &T) -> std::io::Result<()>;
    fn flush(&mut self) -> std::io::Result<()>;
    fn sync(&mut self) -> std::io::Result<()>;
}

fn open_record(path: &Path) -> std::io::Result<File> {
    OpenOptions::new().write(true).create_new(true).mode(0o600)
        .custom_flags(O_CLOEXEC | O_NOFOLLOW).open(path)
}

fn create_record_engine<T: Serialize>(path: &Path, record: &T,
    writer: &mut impl RecordWriter) -> std::io::Result<()>
{
    writer.open(path)?;
    writer.encode(record)?;
    writer.flush()?;
    writer.sync()
}

#[derive(Default)]
struct OrdinaryWriter { file: Option<File> }

impl OrdinaryWriter {
    fn file(&mut self) -> std::io::Result<&mut File> {
        self.file.as_mut().ok_or_else(|| std::io::Error::other("record File is absent"))
    }
}

impl RecordWriter for OrdinaryWriter {
    fn open(&mut self, path: &Path) -> std::io::Result<()> {
        self.file = Some(open_record(path)?);
        Ok(())
    }
    fn encode<T: Serialize>(&mut self, record: &T) -> std::io::Result<()> {
        serde_json::to_writer(self.file()?, record).map_err(std::io::Error::other)
    }
    fn flush(&mut self) -> std::io::Result<()> { self.file()?.flush() }
    fn sync(&mut self) -> std::io::Result<()> { self.file()?.sync_all() }
}

pub(super) fn create_record<T: Serialize>(path: &Path, record: &T) -> std::io::Result<()> {
    create_record_engine(path, record, &mut OrdinaryWriter::default())
}

/// Owns both actual native File destinations and a whole refused replacement.
pub(crate) struct RetainedProcessRecordWriteV1 {
    temporary: Option<PathBuf>,
    opened: Option<std::io::Result<File>>,
    encoded: Option<Result<(), serde_json::Error>>,
    flushed: Option<std::io::Result<()>>,
    synced: Option<std::io::Result<()>>,
    created: Option<std::io::Result<()>>,
    renamed: Option<std::io::Result<()>>,
    directory: Option<std::io::Result<File>>,
    directory_synced: Option<std::io::Result<()>>,
    entered: bool,
    complete: bool,
}

impl RetainedProcessRecordWriteV1 {
    pub(crate) fn new() -> Self {
        Self { temporary: None, opened: None, encoded: None, flushed: None,
            synced: None, created: None, renamed: None, directory: None,
            directory_synced: None, entered: false, complete: false }
    }

    fn file(&mut self) -> std::io::Result<&mut File> {
        self.opened.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or_else(|| std::io::Error::other("record native prefix is retained"))
    }

    pub(super) fn create_once(&mut self, ledger: &Ledger, path: &Path, record: &ProcessRecord)
        -> Result<(), GuestProcessEffectErrorV1>
    {
        if self.entered { return Err(GuestProcessEffectErrorV1::AmbiguousEffect); }
        self.entered = true;
        self.created = Some(create_record_engine(path, record, self));
        if !self.created.as_ref().is_some_and(Result::is_ok) {
            return Err(GuestProcessEffectErrorV1::AmbiguousEffect);
        }
        self.finish_directory(ledger)
    }

    fn finish_directory(&mut self, ledger: &Ledger) -> Result<(), GuestProcessEffectErrorV1> {
        self.directory = Some(File::open(&ledger.root));
        let Some(Ok(directory)) = self.directory.as_ref() else {
            return Err(GuestProcessEffectErrorV1::AmbiguousEffect);
        };
        self.directory_synced = Some(directory.sync_all());
        if !self.directory_synced.as_ref().is_some_and(Result::is_ok) {
            return Err(GuestProcessEffectErrorV1::AmbiguousEffect);
        }
        self.complete = true;
        // The full write and its directory post have completed. Failed raw
        // files never reach this positive disposition.
        drop(self.opened.take());
        drop(self.directory.take());
        Ok(())
    }

    pub(super) fn replace_once(&mut self, ledger: &Ledger, path: &Path, record: &ProcessRecord)
        -> Result<(), GuestProcessEffectErrorV1>
    {
        if self.entered { return Err(GuestProcessEffectErrorV1::AmbiguousEffect); }
        self.entered = true;
        self.temporary = Some(path.with_extension("next"));
        let temporary = self.temporary.take().ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?;
        self.created = Some(create_record_engine(&temporary, record, self));
        self.temporary = Some(temporary);
        if !self.created.as_ref().is_some_and(Result::is_ok) {
            return Err(GuestProcessEffectErrorV1::AmbiguousEffect);
        }
        self.renamed = Some(fs::rename(self.temporary.as_ref()
            .ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?, path));
        if !self.renamed.as_ref().is_some_and(Result::is_ok) {
            return Err(GuestProcessEffectErrorV1::AmbiguousEffect);
        }
        self.finish_directory(ledger)
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        fn cause<T, E: std::error::Error + 'static>(slot: &Option<Result<T, E>>)
            -> Option<&(dyn std::error::Error + 'static)>
        { slot.as_ref()?.as_ref().err().map(|cause| cause as _) }
        cause(&self.opened).or_else(|| cause(&self.encoded))
            .or_else(|| cause(&self.flushed)).or_else(|| cause(&self.synced))
            .or_else(|| cause(&self.created)).or_else(|| cause(&self.renamed))
            .or_else(|| cause(&self.directory)).or_else(|| cause(&self.directory_synced))
    }
}

fn retained_status<T>(result: &Option<std::io::Result<T>>) -> std::io::Result<()> {
    if result.as_ref().is_some_and(Result::is_ok) { Ok(()) }
    else { Err(std::io::Error::other("record native cause retained")) }
}

impl RecordWriter for RetainedProcessRecordWriteV1 {
    fn open(&mut self, path: &Path) -> std::io::Result<()> {
        self.opened = Some(open_record(path));
        retained_status(&self.opened)
    }
    fn encode<T: Serialize>(&mut self, record: &T) -> std::io::Result<()> {
        self.encoded = Some(serde_json::to_writer(self.file()?, record));
        if self.encoded.as_ref().is_some_and(Result::is_ok) { Ok(()) }
        else { Err(std::io::Error::other("record serialization cause retained")) }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.flushed = Some(self.file()?.flush());
        retained_status(&self.flushed)
    }
    fn sync(&mut self) -> std::io::Result<()> {
        self.synced = Some(self.file()?.sync_all());
        retained_status(&self.synced)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd as _;

    struct RefusedEncoding;

    impl Serialize for RefusedEncoding {
        fn serialize<S: serde::Serializer>(&self, _serializer: S) -> Result<S::Ok, S::Error> {
            Err(serde::ser::Error::custom("actual selected serialization refusal"))
        }
    }

    fn ledger(root: &Path) -> Ledger {
        Ledger { root: root.to_path_buf(), effect_barrier: Arc::new(Mutex::new(())),
            live: Arc::new(Mutex::new(crate::process::LiveProcessRegistryV1::default())) }
    }

    #[test]
    fn failed_actual_encoding_retains_the_open_file_and_first_cause() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("failed-row");
        let mut original = RetainedProcessRecordWriteV1::new();
        original.created = Some(create_record_engine(&path, &RefusedEncoding, &mut original));
        assert!(original.created.as_ref().unwrap().is_err());
        let file = original.opened.as_ref().unwrap().as_ref().unwrap();
        assert!(rustix::fs::fcntl_getfl(file).is_ok());
        assert!(original.flushed.is_none());
        assert!(original.synced.is_none());
        assert!(original.failure().unwrap().to_string().contains("actual selected serialization refusal"));
        assert!(path.is_file());
    }

    #[test]
    fn only_actual_record_and_directory_completion_closes_transient_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("positive-row");
        let mut original = RetainedProcessRecordWriteV1::new();
        original.created = Some(create_record_engine(&path, &[1_u8, 2, 3], &mut original));
        assert!(original.created.as_ref().unwrap().is_ok());
        let raw = original.opened.as_ref().unwrap().as_ref().unwrap().as_raw_fd();
        original.finish_directory(&ledger(directory.path())).unwrap();
        assert!(original.complete);
        assert!(original.opened.is_none());
        assert!(original.directory.is_none());
        assert!(original.failure().is_none());
        // No intervening open can reuse this actual just-closed descriptor.
        assert!(!std::path::Path::new(&format!("/proc/self/fd/{raw}")).exists());
        assert_eq!(fs::read(&path).unwrap(), b"[1,2,3]");
    }
}
