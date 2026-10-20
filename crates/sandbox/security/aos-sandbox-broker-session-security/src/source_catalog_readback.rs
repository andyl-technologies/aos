//! Fixed, nonauthorizing SourceProvider catalog reads and retained native DATA.
//!
//! The installer and concrete service share one protected fixed-root recipe.
//! Returned bytes and native comparisons confer no signature, startup, session,
//! Source row, current-head, effect or financial authority.

use std::fs::File;
use std::io::{Read as _, Seek as _};
use std::os::fd::{AsFd as _, OwnedFd};
use std::path::Path;

use aos_sandbox_linux::path::{BeneathRoot, ResolveOptions, ResolvedPath};
use aos_sandbox_linux::seqpacket::SeqpacketError;
use aos_sandbox_source_provider::ProviderLedgerError;
use rustix::fs::{FileType, Mode, OFlags, Stat, fstat, open, openat};
use rustix::io::fcntl_dupfd_cloexec;

use crate::ProductionBrokerSessionActivationErrorV1;
use crate::production_source_provider_catalog::{
    MAXIMUM_CATALOG_ROWS_BYTES, catalog_rows_head, same_stable_metadata,
};

const STATE_ROOT: &str = "/var/lib/aos/source-provider";
const CATALOG_PUBLICATION: &str = "current-catalog-publication";
const CATALOG_PUBLICATION_BYTES: usize = 520;

/// Reports failure before a SourceProvider owner becomes authenticated.
#[derive(Debug, thiserror::Error)]
pub enum ProductionSourceProviderIngressErrorV1 {
    /// The exact systemd activation envelope was absent or malformed.
    #[error("SourceProvider activation failed: {0}")]
    Activation(#[from] ProductionBrokerSessionActivationErrorV1),
    /// The fixed listener or one accepted child was invalid.
    #[error("SourceProvider listener failed: {0}")]
    Listener(#[from] SeqpacketError),
    /// The current catalog publication was absent or unprotected.
    #[error("SourceProvider catalog publication failed: {0}")]
    Catalog(&'static str),
    /// Fixed custody, verifier, or journal admission failed.
    #[error("SourceProvider owner admission failed: {0}")]
    Owner(#[from] ProviderLedgerError),
}

// Local expansion keeps the original consuming/error/drop sequence. Selected
// expansion parks each returned Result before the following observation.
macro_rules! catalog_read_step {
    (Local, $pending:ident, $field:ident, $expression:expr, $label:literal) => {
        $expression.map_err(|_| ProductionSourceProviderIngressErrorV1::Catalog($label))?
    };
    (Retained, $pending:ident, $field:ident, $expression:expr, $label:literal) => {{
        $pending.$field = Some($expression);
        match $pending.$field.as_ref() {
            Some(Ok(value)) => value,
            _ => return Err(ProductionSourceProviderIngressErrorV1::Catalog($label)),
        }
    }};
}

macro_rules! catalog_resolution_root {
    (Local, $pending:ident, $root:ident) => {
        BeneathRoot::from_owned($root)
            .map_err(|_| ProductionSourceProviderIngressErrorV1::Catalog("filesystem root"))?
    };
    (Retained, $pending:ident, $root:ident) => {{
        $pending.root_duplicate = Some(fcntl_dupfd_cloexec($root, 0));
        let duplicate = match $pending.root_duplicate.take() {
            Some(Ok(duplicate)) => duplicate,
            other => {
                $pending.root_duplicate = other;
                return Err(ProductionSourceProviderIngressErrorV1::Catalog("filesystem root"));
            }
        };
        // The same raw original remains in filesystem_root. This unchanged
        // lower consuming validator may still lose its unreturned duplicate.
        $pending.checked_root = Some(BeneathRoot::from_owned(duplicate));
        match $pending.checked_root.as_ref() {
            Some(Ok(root)) => root,
            _ => return Err(ProductionSourceProviderIngressErrorV1::Catalog("filesystem root")),
        }
    }};
}

macro_rules! catalog_read_file {
    (Local, $pending:ident, $descriptor:ident) => {
        File::from($descriptor)
    };
    (Retained, $pending:ident, $descriptor:ident) => {{
        // All slot checks precede the infallible raw-FD-to-File move.
        if $pending.file.is_some() || !matches!($pending.descriptor.as_ref(), Some(Ok(_))) {
            return Err(ProductionSourceProviderIngressErrorV1::Catalog("publication file custody"));
        }
        match $pending.descriptor.take() {
            Some(Ok(descriptor)) => $pending.file = Some(File::from(descriptor)),
            other => {
                $pending.descriptor = other;
                return Err(ProductionSourceProviderIngressErrorV1::Catalog("publication file custody"));
            }
        }
        match $pending.file.as_mut() {
            Some(file) => file,
            None => return Err(ProductionSourceProviderIngressErrorV1::Catalog("publication file custody")),
        }
    }};
}

macro_rules! catalog_read_bytes {
    (Local, $pending:ident, $count:ident) => {
        vec![0; $count]
    };
    (Retained, $pending:ident, $count:ident) => {{
        $pending.bytes.resize($count, 0);
        &mut $pending.bytes
    }};
}

macro_rules! catalog_read_tail {
    (Local, $pending:ident) => { [0] };
    (Retained, $pending:ident) => { &mut $pending.trailing };
}

macro_rules! catalog_read_complete {
    (Local, $bytes:ident) => { Ok($bytes) };
    (Retained, $bytes:ident) => { Ok(()) };
}

macro_rules! read_catalog_recipe {
    ($name:ident, $maximum:ident, $disposition:ident, $pending:ident) => {{
        let filesystem_root = catalog_read_step!(
            $disposition, $pending, filesystem_root,
            open("/", OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty()),
            "filesystem root"
        );
        let root = catalog_resolution_root!($disposition, $pending, filesystem_root);
        let relative = Path::new(STATE_ROOT).strip_prefix("/")
            .map_err(|_| ProductionSourceProviderIngressErrorV1::Catalog("fixed state path"))?;
        let directory = catalog_read_step!(
            $disposition, $pending, directory,
            root.resolve(relative, ResolveOptions { no_mount_crossing: false, require_directory: true }),
            "state directory"
        );
        let directory_stat = catalog_read_step!(
            $disposition, $pending, directory_stat, fstat(directory.as_fd()), "state metadata"
        );
        if FileType::from_raw_mode(directory_stat.st_mode) != FileType::Directory
            || directory_stat.st_uid != 0 || directory_stat.st_mode & 0o7777 != 0o700
        {
            return Err(ProductionSourceProviderIngressErrorV1::Catalog("state directory is not protected"));
        }

        let descriptor = catalog_read_step!(
            $disposition, $pending, descriptor,
            openat(directory.as_fd(), $name, OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC, Mode::empty()),
            "publication file"
        );
        let before = catalog_read_step!(
            $disposition, $pending, before, fstat(&descriptor), "publication metadata"
        );
        if !valid_catalog_metadata(CatalogMetadata::capture(&before), $maximum) {
            return Err(ProductionSourceProviderIngressErrorV1::Catalog("publication is not protected"));
        }

        let mut file = catalog_read_file!($disposition, $pending, descriptor);
        let byte_count = usize::try_from(before.st_size)
            .map_err(|_| ProductionSourceProviderIngressErrorV1::Catalog("catalog file length"))?;
        let mut bytes = catalog_read_bytes!($disposition, $pending, byte_count);
        catalog_read_step!(
            $disposition, $pending, read_result, file.read_exact(&mut bytes[..]), "publication bytes"
        );
        let mut trailing = catalog_read_tail!($disposition, $pending);
        let tail_count = catalog_read_step!(
            $disposition, $pending, tail_result, file.read(&mut trailing[..]), "publication tail"
        );
        if *catalog_tail_count!($disposition, tail_count) != 0 {
            return Err(ProductionSourceProviderIngressErrorV1::Catalog("publication has trailing bytes"));
        }
        let after = catalog_read_step!(
            $disposition, $pending, after, fstat(file.as_fd()), "publication recheck"
        );
        if !same_stable_metadata(&before, &after) {
            return Err(ProductionSourceProviderIngressErrorV1::Catalog("publication changed while being read"));
        }
        catalog_read_complete!($disposition, bytes)
    }};
}

macro_rules! catalog_tail_count {
    (Local, $count:ident) => { &$count };
    (Retained, $count:ident) => { $count };
}


fn validate_catalog_pair_data(
    publication: &[u8],
    rows: &[u8],
    digest: aos_sandbox_model::ObjectDigest,
) -> Result<(), ProductionSourceProviderIngressErrorV1> {
    let (generation, namespace, rows_digest) = catalog_rows_head(rows)
        .ok_or(ProductionSourceProviderIngressErrorV1::Catalog("catalog rows format"))?;
    if rows_digest != digest || publication.get(72..104) != Some(namespace.as_bytes().as_slice())
        || publication.get(104..112) != Some(generation.to_be_bytes().as_slice())
    {
        return Err(ProductionSourceProviderIngressErrorV1::Catalog("manifest does not match publication"));
    }
    Ok(())
}


#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CatalogMetadata {
    size: i64,
    mode: u32,
    uid: u32,
    links: u64,
}

impl CatalogMetadata {
    const fn capture(stat: &Stat) -> Self {
        Self {
            size: stat.st_size,
            mode: stat.st_mode,
            uid: stat.st_uid,
            links: stat.st_nlink,
        }
    }
}

fn read_protected_catalog_publication() -> Result<Vec<u8>, ProductionSourceProviderIngressErrorV1> {
    let bytes = read_protected_catalog_file(CATALOG_PUBLICATION, CATALOG_PUBLICATION_BYTES)?;
    if bytes.len() != CATALOG_PUBLICATION_BYTES {
        return Err(ProductionSourceProviderIngressErrorV1::Catalog(
            "publication length",
        ));
    }
    Ok(bytes)
}

fn read_protected_catalog_file(
    name: &str,
    maximum_bytes: usize,
) -> Result<Vec<u8>, ProductionSourceProviderIngressErrorV1> {
    read_catalog_recipe!(name, maximum_bytes, Local, unused)
}

fn valid_catalog_metadata(metadata: CatalogMetadata, maximum_bytes: usize) -> bool {
    FileType::from_raw_mode(metadata.mode) == FileType::RegularFile
        && metadata.uid == 0
        && metadata.links == 1
        && metadata.mode & 0o7777 == 0o600
        && metadata.size > 0
        && metadata.size <= maximum_bytes as i64
}

/// Retains returned originals and actual read failures for one fixed catalog file.
/// The one extra root duplicate is not a second authority or reopening path.
#[derive(Default)]
struct SelectedCatalogReadV1 {
    filesystem_root: Option<Result<OwnedFd, rustix::io::Errno>>,
    root_duplicate: Option<Result<OwnedFd, rustix::io::Errno>>,
    checked_root: Option<aos_sandbox_linux::Result<BeneathRoot>>,
    directory: Option<aos_sandbox_linux::Result<ResolvedPath>>,
    directory_stat: Option<Result<Stat, rustix::io::Errno>>,
    descriptor: Option<Result<OwnedFd, rustix::io::Errno>>,
    before: Option<Result<Stat, rustix::io::Errno>>,
    file: Option<File>,
    bytes: Vec<u8>,
    read_result: Option<std::io::Result<()>>,
    trailing: [u8; 1],
    tail_result: Option<std::io::Result<usize>>,
    after: Option<Result<Stat, rustix::io::Errno>>,
    named_directory: Option<aos_sandbox_linux::Result<ResolvedPath>>,
    named_directory_metadata: Option<Result<Stat, rustix::io::Errno>>,
    named_after_directory: Option<aos_sandbox_linux::Result<ResolvedPath>>,
    named_after_directory_metadata: Option<Result<Stat, rustix::io::Errno>>,
    named_descriptor: Option<Result<OwnedFd, rustix::io::Errno>>,
    named_metadata: Option<Result<Stat, rustix::io::Errno>>,
    named_after_descriptor: Option<Result<OwnedFd, rustix::io::Errno>>,
    named_after_metadata: Option<Result<Stat, rustix::io::Errno>>,
    repeat_directory: Option<Result<Stat, rustix::io::Errno>>,
    repeat_before: Option<Result<Stat, rustix::io::Errno>>,
    rewind: Option<std::io::Result<()>>,
    repeat_bytes: Vec<u8>,
    repeat_read: Option<std::io::Result<()>>,
    repeat_trailing: [u8; 1],
    repeat_tail: Option<std::io::Result<usize>>,
    repeat_after: Option<Result<Stat, rustix::io::Errno>>,
    attempted: bool,
    complete: bool,
}

/// Borrows a retained fixed-catalog native failure without resampling.
pub enum CatalogReadFailureRefV1<'owner> {
    /// The same native descriptor operation failed.
    Kernel(&'owner rustix::io::Errno),
    /// The same bounded path resolution failed.
    Path(&'owner aos_sandbox_linux::Error),
    /// The same read or seek failed.
    Read(&'owner std::io::Error),
}

macro_rules! catalog_failure_slot {
    ($owner:ident, $slot:ident, $kind:ident) => {
        if let Some(Err(error)) = $owner.$slot.as_ref() {
            return Some(CatalogReadFailureRefV1::$kind(error));
        }
    };
}

impl SelectedCatalogReadV1 {
    fn failure(&self) -> Option<CatalogReadFailureRefV1<'_>> {
        catalog_failure_slot!(self, filesystem_root, Kernel);
        catalog_failure_slot!(self, root_duplicate, Kernel);
        catalog_failure_slot!(self, checked_root, Path);
        catalog_failure_slot!(self, directory, Path);
        catalog_failure_slot!(self, directory_stat, Kernel);
        catalog_failure_slot!(self, descriptor, Kernel);
        catalog_failure_slot!(self, before, Kernel);
        catalog_failure_slot!(self, read_result, Read);
        catalog_failure_slot!(self, tail_result, Read);
        catalog_failure_slot!(self, after, Kernel);
        catalog_failure_slot!(self, named_directory, Path);
        catalog_failure_slot!(self, named_directory_metadata, Kernel);
        catalog_failure_slot!(self, repeat_directory, Kernel);
        catalog_failure_slot!(self, named_descriptor, Kernel);
        catalog_failure_slot!(self, named_metadata, Kernel);
        catalog_failure_slot!(self, repeat_before, Kernel);
        catalog_failure_slot!(self, rewind, Read);
        catalog_failure_slot!(self, repeat_read, Read);
        catalog_failure_slot!(self, repeat_tail, Read);
        catalog_failure_slot!(self, repeat_after, Kernel);
        catalog_failure_slot!(self, named_after_directory, Path);
        catalog_failure_slot!(self, named_after_directory_metadata, Kernel);
        catalog_failure_slot!(self, named_after_descriptor, Kernel);
        catalog_failure_slot!(self, named_after_metadata, Kernel);
        None
    }

    fn read_once(&mut self, name: &str, maximum_bytes: usize) -> Result<(), ProductionSourceProviderIngressErrorV1> {
        if self.attempted {
            return Err(ProductionSourceProviderIngressErrorV1::Catalog("catalog read already attempted"));
        }
        self.attempted = true;
        let result = (|| read_catalog_recipe!(name, maximum_bytes, Retained, self))();
        self.complete = result.is_ok();
        result
    }

    fn recheck(&mut self, name: &str) -> Result<(), ProductionSourceProviderIngressErrorV1> {
        if !self.complete {
            return Err(ProductionSourceProviderIngressErrorV1::Catalog("catalog read is not current"));
        }
        self.complete = false;
        let root = match self.checked_root.as_ref() {
            Some(Ok(root)) => root,
            _ => return Err(ProductionSourceProviderIngressErrorV1::Catalog("filesystem root custody")),
        };
        let directory = match self.directory.as_ref() {
            Some(Ok(directory)) => directory,
            _ => return Err(ProductionSourceProviderIngressErrorV1::Catalog("state directory custody")),
        };
        let original_directory = match self.directory_stat.as_ref() {
            Some(Ok(metadata)) => metadata,
            _ => return Err(ProductionSourceProviderIngressErrorV1::Catalog("state metadata custody")),
        };
        let original_metadata = match self.before.as_ref() {
            Some(Ok(metadata)) => metadata,
            _ => return Err(ProductionSourceProviderIngressErrorV1::Catalog("publication metadata custody")),
        };
        let file = self.file.as_mut().ok_or(ProductionSourceProviderIngressErrorV1::Catalog(
            "publication file custody",
        ))?;

        // A fresh named pin is only a comparison with the same original file.
        // It cannot replace that original or renew a changed catalog cut.
        let relative = Path::new(STATE_ROOT).strip_prefix("/")
            .map_err(|_| ProductionSourceProviderIngressErrorV1::Catalog("fixed state path"))?;
        self.named_directory = Some(root.resolve(relative, ResolveOptions {
            no_mount_crossing: false,
            require_directory: true,
        }));
        let named_directory = match self.named_directory.as_ref() {
            Some(Ok(directory)) => directory,
            _ => return Err(ProductionSourceProviderIngressErrorV1::Catalog("state directory name recheck")),
        };
        self.named_directory_metadata = Some(fstat(named_directory.as_fd()));
        if !matches!(self.named_directory_metadata.as_ref(), Some(Ok(metadata))
            if same_stable_metadata(original_directory, metadata))
        {
            return Err(ProductionSourceProviderIngressErrorV1::Catalog("state directory name changed"));
        }
        self.repeat_directory = Some(fstat(directory.as_fd()));
        if !matches!(self.repeat_directory.as_ref(), Some(Ok(metadata))
            if same_stable_metadata(original_directory, metadata))
        {
            return Err(ProductionSourceProviderIngressErrorV1::Catalog("state directory changed"));
        }
        self.named_descriptor = Some(openat(
            directory.as_fd(), name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ));
        let named = match self.named_descriptor.as_ref() {
            Some(Ok(descriptor)) => descriptor,
            _ => return Err(ProductionSourceProviderIngressErrorV1::Catalog("publication name recheck")),
        };
        self.named_metadata = Some(fstat(named));
        if !matches!(self.named_metadata.as_ref(), Some(Ok(metadata))
            if same_stable_metadata(original_metadata, metadata))
        {
            return Err(ProductionSourceProviderIngressErrorV1::Catalog("publication name changed"));
        }
        self.repeat_before = Some(fstat(file.as_fd()));
        if !matches!(self.repeat_before.as_ref(), Some(Ok(metadata))
            if same_stable_metadata(original_metadata, metadata))
        {
            return Err(ProductionSourceProviderIngressErrorV1::Catalog("publication changed"));
        }

        self.rewind = Some(file.rewind());
        if !matches!(self.rewind.as_ref(), Some(Ok(()))) {
            return Err(ProductionSourceProviderIngressErrorV1::Catalog("publication rewind"));
        }
        self.repeat_bytes.resize(self.bytes.len(), 0);
        self.repeat_read = Some(file.read_exact(&mut self.repeat_bytes));
        if !matches!(self.repeat_read.as_ref(), Some(Ok(()))) {
            return Err(ProductionSourceProviderIngressErrorV1::Catalog("publication reread"));
        }
        self.repeat_tail = Some(file.read(&mut self.repeat_trailing));
        if !matches!(self.repeat_tail.as_ref(), Some(Ok(0))) {
            return Err(ProductionSourceProviderIngressErrorV1::Catalog("publication reread tail"));
        }
        self.repeat_after = Some(fstat(file.as_fd()));
        if self.repeat_bytes != self.bytes
            || !matches!(self.repeat_after.as_ref(), Some(Ok(metadata))
                if same_stable_metadata(original_metadata, metadata))
        {
            return Err(ProductionSourceProviderIngressErrorV1::Catalog("publication changed during reread"));
        }
        self.named_after_directory = Some(root.resolve(relative, ResolveOptions {
            no_mount_crossing: false,
            require_directory: true,
        }));
        let named_after_directory = match self.named_after_directory.as_ref() {
            Some(Ok(directory)) => directory,
            _ => return Err(ProductionSourceProviderIngressErrorV1::Catalog("state final directory name recheck")),
        };
        self.named_after_directory_metadata = Some(fstat(named_after_directory.as_fd()));
        if !matches!(self.named_after_directory_metadata.as_ref(), Some(Ok(metadata))
            if same_stable_metadata(original_directory, metadata))
        {
            return Err(ProductionSourceProviderIngressErrorV1::Catalog("state final directory name changed"));
        }
        self.named_after_descriptor = Some(openat(
            named_after_directory.as_fd(), name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ));
        let named_after = match self.named_after_descriptor.as_ref() {
            Some(Ok(descriptor)) => descriptor,
            _ => return Err(ProductionSourceProviderIngressErrorV1::Catalog("publication final name recheck")),
        };
        self.named_after_metadata = Some(fstat(named_after));
        if !matches!(self.named_after_metadata.as_ref(), Some(Ok(metadata))
            if same_stable_metadata(original_metadata, metadata))
        {
            return Err(ProductionSourceProviderIngressErrorV1::Catalog("publication final name changed"));
        }
        self.complete = true;
        Ok(())
    }
}

/// Retains the two fixed native catalog readers and their untrusted bytes.
///
/// Default construction is inert. This owner authenticates no catalog signature,
/// Source startup, peer, selected resource, effect, current head or funding.
#[derive(Default)]
pub struct SelectedCatalogPairV1 {
    publication: SelectedCatalogReadV1,
    rows: SelectedCatalogReadV1,
    rows_name: Option<String>,
    attempted: bool,
    complete: bool,
}

impl SelectedCatalogPairV1 {
    /// Borrows the first retained native read failure.
    pub fn failure(&self) -> Option<CatalogReadFailureRefV1<'_>> {
        self.publication.failure().or_else(|| self.rows.failure())
    }

    pub(crate) fn matches_original_bytes(&self, publication: &[u8], rows: &[u8]) -> bool {
        self.complete && self.publication.bytes == publication && self.rows.bytes == rows
    }

    pub(crate) fn matches_written_originals(&self, directory: &Stat, publication: &Stat, rows: &Stat) -> bool {
        self.complete
            && matches!(self.publication.directory_stat.as_ref(), Some(Ok(actual)) if same_stable_metadata(directory, actual))
            && matches!(self.rows.directory_stat.as_ref(), Some(Ok(actual)) if same_stable_metadata(directory, actual))
            && matches!(self.publication.before.as_ref(), Some(Ok(actual)) if same_stable_metadata(publication, actual))
            && matches!(self.rows.before.as_ref(), Some(Ok(actual)) if same_stable_metadata(rows, actual))
    }

    /// Reads the fixed publication and its content-addressed manifest once.
    ///
    /// # Errors
    /// Rejects reentry, unsafe metadata, native failures or a mismatched pair.
    pub fn read_once(&mut self) -> Result<(), ProductionSourceProviderIngressErrorV1> {
        if self.attempted {
            return Err(ProductionSourceProviderIngressErrorV1::Catalog("catalog pair already attempted"));
        }
        self.attempted = true;
        self.publication.read_once(CATALOG_PUBLICATION, CATALOG_PUBLICATION_BYTES)?;
        if self.publication.bytes.len() != CATALOG_PUBLICATION_BYTES {
            return Err(ProductionSourceProviderIngressErrorV1::Catalog("publication length"));
        }
        let digest = aos_sandbox_model::ObjectDigest::from_bytes(
            self.publication.bytes[112..144].try_into()
                .map_err(|_| ProductionSourceProviderIngressErrorV1::Catalog("publication digest"))?,
        );
        self.rows_name = Some(crate::production_source_provider_catalog::manifest_filename(digest));
        let name = self.rows_name.as_deref().ok_or(
            ProductionSourceProviderIngressErrorV1::Catalog("catalog rows name"),
        )?;
        self.rows.read_once(name, MAXIMUM_CATALOG_ROWS_BYTES)?;
        validate_catalog_pair_data(&self.publication.bytes, &self.rows.bytes, digest)?;
        self.complete = true;
        Ok(())
    }

    /// Rechecks the same held fixed catalog originals without replacement.
    ///
    /// # Errors
    /// Rejects an incomplete pair or drift in names, metadata or bytes.
    pub fn recheck(&mut self) -> Result<(), ProductionSourceProviderIngressErrorV1> {
        if !self.complete {
            return Err(ProductionSourceProviderIngressErrorV1::Catalog("catalog pair is not current"));
        }
        self.complete = false;
        self.publication.recheck(CATALOG_PUBLICATION)?;
        let name = self.rows_name.as_deref().ok_or(
            ProductionSourceProviderIngressErrorV1::Catalog("catalog rows name"),
        )?;
        self.rows.recheck(name)?;
        let digest = aos_sandbox_model::ObjectDigest::from_bytes(
            self.publication.bytes[112..144].try_into()
                .map_err(|_| ProductionSourceProviderIngressErrorV1::Catalog("publication digest"))?,
        );
        validate_catalog_pair_data(&self.publication.bytes, &self.rows.bytes, digest)?;
        self.complete = true;
        Ok(())
    }

    /// Borrows the same untrusted publication buffer, including a failed prefix.
    pub fn publication_bytes_data_v1(&self) -> &[u8] {
        &self.publication.bytes
    }

    /// Borrows the same untrusted manifest buffer, including a failed prefix.
    pub fn manifest_bytes_data_v1(&self) -> &[u8] {
        &self.rows.bytes
    }
}

/// Reads the fixed publication and content-addressed manifest as untrusted DATA.
///
/// The genuine caller owns listener, protected Provider and startup bookends.
/// No caller-selected pathname or descriptor is accepted.
///
/// # Errors
/// Rejects unsafe fixed-root metadata, native I/O failure or a mismatched pair.
pub fn read_current_catalog_manifest_data_v1(
) -> Result<(Vec<u8>, Vec<u8>), ProductionSourceProviderIngressErrorV1> {
        let publication = read_protected_catalog_publication()?;
        let digest =
            aos_sandbox_model::ObjectDigest::from_bytes(publication[112..144].try_into().map_err(
                |_| ProductionSourceProviderIngressErrorV1::Catalog("publication digest"),
            )?);
        let name = crate::production_source_provider_catalog::manifest_filename(digest);
        let manifest_bytes = read_protected_catalog_file(&name, MAXIMUM_CATALOG_ROWS_BYTES)?;
        validate_catalog_pair_data(&publication, &manifest_bytes, digest)?;
        Ok((publication, manifest_bytes))
    }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_locator_rejects_unprotected_metadata() {
        let protected = CatalogMetadata {
            size: CATALOG_PUBLICATION_BYTES as i64,
            mode: 0o100600,
            uid: 0,
            links: 1,
        };
        assert!(valid_catalog_metadata(protected, CATALOG_PUBLICATION_BYTES));
        assert!(!valid_catalog_metadata(
            CatalogMetadata {
                uid: 1000,
                ..protected
            },
            CATALOG_PUBLICATION_BYTES
        ));
        assert!(!valid_catalog_metadata(
            CatalogMetadata {
                links: 2,
                ..protected
            },
            CATALOG_PUBLICATION_BYTES
        ));
        assert!(!valid_catalog_metadata(
            CatalogMetadata {
                mode: 0o100644,
                ..protected
            },
            CATALOG_PUBLICATION_BYTES
        ));
        assert!(!valid_catalog_metadata(
            CatalogMetadata {
                mode: 0o120600,
                ..protected
            },
            CATALOG_PUBLICATION_BYTES
        ));
        assert!(!valid_catalog_metadata(
            CatalogMetadata {
                size: CATALOG_PUBLICATION_BYTES as i64 + 1,
                ..protected
            },
            CATALOG_PUBLICATION_BYTES
        ));
    }


    #[test]
    fn failed_read_refuses_reentry_without_replacing_its_native_cause() {
        let mut reader = SelectedCatalogReadV1 {
            filesystem_root: Some(Err(rustix::io::Errno::ACCESS)),
            attempted: true,
            ..SelectedCatalogReadV1::default()
        };

        let result = reader.read_once(CATALOG_PUBLICATION, CATALOG_PUBLICATION_BYTES);

        assert!(result.is_err());
        assert!(matches!(reader.failure(), Some(CatalogReadFailureRefV1::Kernel(error))
            if *error == rustix::io::Errno::ACCESS));
        assert!(reader.checked_root.is_none());
        assert!(reader.directory.is_none());
        assert!(reader.file.is_none());
    }

    #[test]
    fn incomplete_pair_refuses_recheck_without_opening_a_replacement() {
        let mut pair = SelectedCatalogPairV1::default();

        let result = pair.recheck();

        assert!(result.is_err());
        assert!(!pair.complete);
        assert!(pair.publication.filesystem_root.is_none());
        assert!(pair.rows.filesystem_root.is_none());
    }
}
