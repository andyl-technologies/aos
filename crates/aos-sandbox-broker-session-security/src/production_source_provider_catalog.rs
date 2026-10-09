//! Fail-closed installation of the nonauthorizing SourceProvider catalog pair.
//!
//! PID 1 supplies the canonical signed publication and matching row catalog
//! as separate named credentials. The content-addressed catalog is synced
//! first, then the publication locator is atomically replaced. A crash between
//! them can only leave an unusable pair; the fixed owner still authenticates
//! the signature and exact protected journal head after RootMount handshake.

use std::fmt::Write as _;
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::fd::AsFd as _;
use std::path::Path;

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_linux::path::{BeneathRoot, ResolveOptions};
use aos_sandbox_source_provider_protocol::{
    ProviderCatalogManifestV1, ProviderHeldSnapshotCatalogV1,
};
use aos_sandbox_source_provider_security::{
    ProtectedProviderCustodyV1, RevalidatedProviderConfigurationV1,
    SelectedSourceProviderCustodyOpeningV1, SourceProviderSecurityError,
};
use rustix::fs::{
    AtFlags, FileType, Mode, OFlags, Stat, fchmod, fstat, fsync, open, openat, renameat, unlinkat,
};
use rustix::rand::{GetRandomFlags, getrandom};

const STATE_ROOT: &str = "/var/lib/aos/source-provider";
const CREDENTIAL_NAME: &str = "current-catalog-publication";
const MANIFEST_CREDENTIAL_NAME: &str = "current-catalog-manifest";
const PUBLICATION_BYTES: usize = 520;
pub(crate) const MAXIMUM_CATALOG_ROWS_BYTES: usize = 54 + 64 * 328;

/// Reports rejection while installing the nonauthorizing catalog locator.
#[derive(Debug, thiserror::Error)]
pub enum ProductionSourceProviderCatalogInstallErrorV1 {
    /// The installer was not invoked as root.
    #[error("SourceProvider catalog installer requires real and effective UID zero")]
    Identity,
    /// The systemd credential is absent, malformed, or unprotected.
    #[error("SourceProvider catalog credential is invalid: {0}")]
    Credential(&'static str),
    /// The fixed state directory or publication entry is unprotected.
    #[error("SourceProvider catalog state is invalid: {0}")]
    State(&'static str),
    /// Atomic publication or durable sync failed.
    #[error("SourceProvider catalog publication failed: {0}")]
    Publication(&'static str),
}

/// Installs a matching manifest before atomically replacing the publication.
///
/// The installer accepts only a root-owned, singly linked, private regular
/// 520-byte publication, bounded canonical manifest, and a root-owned,
/// mode-0700 state directory. This is storage hygiene, not a signature or
/// currentness decision: the fixed owner still verifies the publication and
/// journal before selecting any resource row.
///
/// # Errors
///
/// Rejects missing root identity, credential or state protection failures,
/// malformed length, unsafe existing entries, or an unsuccessful durable
/// write/rename. The old publication is retained until the atomic rename.
pub fn install_fixed_source_provider_catalog_credential()
-> Result<(), ProductionSourceProviderCatalogInstallErrorV1> {
    if !rustix::process::getuid().is_root() || !rustix::process::geteuid().is_root() {
        return Err(ProductionSourceProviderCatalogInstallErrorV1::Identity);
    }

    let publication = read_systemd_credential(CREDENTIAL_NAME, PUBLICATION_BYTES)?;
    let manifest_bytes =
        read_systemd_credential(MANIFEST_CREDENTIAL_NAME, MAXIMUM_CATALOG_ROWS_BYTES)?;
    let (generation, namespace, digest) = catalog_rows_head(&manifest_bytes).ok_or(
        ProductionSourceProviderCatalogInstallErrorV1::Credential("catalog rows are noncanonical"),
    )?;
    if !publication_matches_rows(&publication, generation, namespace, digest) {
        return Err(ProductionSourceProviderCatalogInstallErrorV1::Credential(
            "manifest does not match publication head",
        ));
    }
    let state = open_private_state_directory()?;
    let manifest_name = manifest_filename(digest);
    install_in_directory(state.as_fd(), &manifest_name, &manifest_bytes, 0)?;
    install_in_directory(state.as_fd(), CREDENTIAL_NAME, &publication, 0)
}

fn publication_matches_rows(
    publication: &[u8],
    generation: u64,
    namespace: ObjectDigest,
    digest: ObjectDigest,
) -> bool {
    publication.len() == PUBLICATION_BYTES
        && publication[0..8] == *b"AOSPCP01"
        && publication[72..104] == *namespace.as_bytes()
        && publication[104..112] == generation.to_be_bytes()
        && publication[112..144] == *digest.as_bytes()
}

/// Parses either supported canonical row family without promoting it to authority.
pub(crate) fn catalog_rows_head(bytes: &[u8]) -> Option<(u64, ObjectDigest, ObjectDigest)> {
    if let Ok(rows) = ProviderCatalogManifestV1::from_canonical_bytes(bytes) {
        return Some((rows.generation(), rows.namespace_digest(), rows.digest()));
    }
    let rows = ProviderHeldSnapshotCatalogV1::from_canonical_bytes(bytes).ok()?;
    Some((rows.generation(), rows.namespace_digest(), rows.digest()))
}

pub(crate) fn manifest_filename(digest: ObjectDigest) -> String {
    let mut filename = String::from("catalog-manifest-");
    for octet in digest.as_bytes() {
        use std::fmt::Write as _;
        let _ = write!(&mut filename, "{octet:02x}");
    }
    filename
}

// The Legacy expansion preserves its local cleanup interval. Selected expansion
// deposits each returned Result and read prefix before the next observation.
macro_rules! catalog_install_step {
    (Legacy, $pending:ident, $slot:ident, $expression:expr, $error:expr) => {
        $expression.map_err(|_| $error)?
    };
    (Selected, $pending:ident, $slot:ident, $expression:expr, $error:expr) => {{
        $pending.$slot = Some($expression);
        match $pending.$slot.as_ref() {
            Some(Ok(value)) => value,
            _ => return Err($error),
        }
    }};
}

macro_rules! catalog_install_file {
    (Legacy, $pending:ident, $descriptor:ident) => { File::from($descriptor) };
    (Selected, $pending:ident, $descriptor:ident) => {{
        if $pending.file.is_some() || !matches!($pending.descriptor.as_ref(), Some(Ok(_))) {
            return Err(ProductionSourceProviderCatalogInstallErrorV1::Credential("file custody"));
        }
        match $pending.descriptor.take() {
            Some(Ok(descriptor)) => $pending.file = Some(File::from(descriptor)),
            other => {
                $pending.descriptor = other;
                return Err(ProductionSourceProviderCatalogInstallErrorV1::Credential("file custody"));
            }
        }
        match $pending.file.as_mut() {
            Some(file) => file,
            None => return Err(ProductionSourceProviderCatalogInstallErrorV1::Credential("file custody")),
        }
    }};
}

macro_rules! catalog_install_read_bytes {
    (Legacy, $pending:ident, $count:ident) => { vec![0; $count] };
    (Selected, $pending:ident, $count:ident) => {{
        $pending.bytes.resize($count, 0);
        &mut $pending.bytes
    }};
}

macro_rules! catalog_install_tail {
    (Legacy, $pending:ident) => { [0] };
    (Selected, $pending:ident) => { &mut $pending.trailing };
}

macro_rules! catalog_install_tail_count {
    (Legacy, $count:ident) => { $count };
    (Selected, $count:ident) => { *$count };
}

macro_rules! catalog_install_read_complete {
    (Legacy, $bytes:ident) => { Ok($bytes) };
    (Selected, $bytes:ident) => { Ok::<(), ProductionSourceProviderCatalogInstallErrorV1>(()) };
}

macro_rules! read_systemd_catalog_recipe {
    ($name:ident, $maximum:ident, $disposition:ident, $pending:ident) => {{
        let directory = catalog_install_credential_directory!($disposition, $pending);
        let directory = Path::new(&directory);
        if !directory.is_absolute() {
            return Err(ProductionSourceProviderCatalogInstallErrorV1::Credential("directory is not absolute"));
        }
        let directory_fd = catalog_install_step!(
            $disposition, $pending, directory,
            open(directory, OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty()),
            ProductionSourceProviderCatalogInstallErrorV1::Credential("directory")
        );
        let directory_stat = catalog_install_step!(
            $disposition, $pending, directory_stat, fstat(&directory_fd),
            ProductionSourceProviderCatalogInstallErrorV1::Credential("directory metadata")
        );
        if FileType::from_raw_mode(directory_stat.st_mode) != FileType::Directory
            || directory_stat.st_uid != 0
            || !matches!(directory_stat.st_mode & 0o7777, 0o500 | 0o700)
        {
            return Err(ProductionSourceProviderCatalogInstallErrorV1::Credential("directory protection"));
        }

        let descriptor = catalog_install_step!(
            $disposition, $pending, descriptor,
            openat(&directory_fd, $name, OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC, Mode::empty()),
            ProductionSourceProviderCatalogInstallErrorV1::Credential("publication file")
        );
        let before = catalog_install_step!(
            $disposition, $pending, before, fstat(&descriptor),
            ProductionSourceProviderCatalogInstallErrorV1::Credential("publication metadata")
        );
        if !valid_credential(&before, $maximum) {
            return Err(ProductionSourceProviderCatalogInstallErrorV1::Credential("publication protection"));
        }

        let mut file = catalog_install_file!($disposition, $pending, descriptor);
        let byte_count = usize::try_from(before.st_size).map_err(|_| {
            ProductionSourceProviderCatalogInstallErrorV1::Credential("publication length")
        })?;
        let mut bytes = catalog_install_read_bytes!($disposition, $pending, byte_count);
        catalog_install_step!(
            $disposition, $pending, read_result, file.read_exact(&mut bytes[..]),
            ProductionSourceProviderCatalogInstallErrorV1::Credential("publication bytes")
        );
        let mut trailing = catalog_install_tail!($disposition, $pending);
        let tail_count = catalog_install_step!(
            $disposition, $pending, tail_result, file.read(&mut trailing[..]),
            ProductionSourceProviderCatalogInstallErrorV1::Credential("publication tail")
        );
        // Keep the old short-circuit: a nonempty tail never performs fstat.
        if catalog_install_tail_count!($disposition, tail_count) != 0
            || !{
                let after = catalog_install_step!(
                    $disposition, $pending, after, fstat(file.as_fd()),
                    ProductionSourceProviderCatalogInstallErrorV1::Credential("publication recheck")
                );
                same_stable_metadata(&before, &after)
            }
        {
            return Err(ProductionSourceProviderCatalogInstallErrorV1::Credential("publication changed"));
        }
        catalog_install_read_complete!($disposition, bytes)
    }};
}

macro_rules! catalog_install_credential_directory {
    (Legacy, $pending:ident) => {
        std::env::var_os("CREDENTIALS_DIRECTORY").ok_or(
            ProductionSourceProviderCatalogInstallErrorV1::Credential("directory is absent"),
        )?
    };
    (Selected, $pending:ident) => {{
        $pending.directory_name = std::env::var_os("CREDENTIALS_DIRECTORY");
        let expected_directory = $pending.directory_role.path();
        match $pending.directory_name.as_ref() {
            Some(directory) if directory.as_os_str() == std::ffi::OsStr::new(expected_directory) => directory,
            Some(_) => return Err(ProductionSourceProviderCatalogInstallErrorV1::Credential("selected directory")),
            None => return Err(ProductionSourceProviderCatalogInstallErrorV1::Credential("directory is absent")),
        }
    }};
}

fn read_systemd_credential(
    name: &str,
    maximum_bytes: usize,
) -> Result<Vec<u8>, ProductionSourceProviderCatalogInstallErrorV1> {
    read_systemd_catalog_recipe!(name, maximum_bytes, Legacy, unused)
}

fn valid_credential(stat: &Stat, maximum_bytes: usize) -> bool {
    FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile
        && stat.st_uid == 0
        && stat.st_nlink == 1
        && stat.st_size > 0
        && stat.st_size <= maximum_bytes as i64
        && matches!(stat.st_mode & 0o7777, 0o400 | 0o600)
}

pub(crate) fn same_stable_metadata(before: &Stat, after: &Stat) -> bool {
    before.st_dev == after.st_dev
        && before.st_ino == after.st_ino
        && before.st_mode == after.st_mode
        && before.st_uid == after.st_uid
        && before.st_gid == after.st_gid
        && before.st_nlink == after.st_nlink
        && before.st_size == after.st_size
        && before.st_mtime == after.st_mtime
        && before.st_mtime_nsec == after.st_mtime_nsec
        && before.st_ctime == after.st_ctime
        && before.st_ctime_nsec == after.st_ctime_nsec
}

macro_rules! catalog_install_root {
    (Legacy, $pending:ident, $filesystem_root:ident) => {
        BeneathRoot::from_owned($filesystem_root)
            .map_err(|_| ProductionSourceProviderCatalogInstallErrorV1::State("filesystem root"))?
    };
    (Selected, $pending:ident, $filesystem_root:ident) => {{
        // Retain the actual original across the existing consuming validator.
        // An unreturned prefix inside that lower validator remains excluded.
        $pending.root_duplicate = Some(rustix::io::fcntl_dupfd_cloexec($filesystem_root, 0));
        let duplicate = match $pending.root_duplicate.take() {
            Some(Ok(duplicate)) => duplicate,
            other => {
                $pending.root_duplicate = other;
                return Err(ProductionSourceProviderCatalogInstallErrorV1::State("filesystem root"));
            }
        };
        $pending.root = Some(BeneathRoot::from_owned(duplicate));
        match $pending.root.as_ref() {
            Some(Ok(root)) => root,
            _ => return Err(ProductionSourceProviderCatalogInstallErrorV1::State("filesystem root")),
        }
    }};
}

macro_rules! catalog_install_state_complete {
    (Legacy, $directory:ident) => { Ok($directory) };
    (Selected, $directory:ident) => { Ok::<(), ProductionSourceProviderCatalogInstallErrorV1>(()) };
}

macro_rules! open_catalog_state_recipe {
    ($disposition:ident, $pending:ident) => {{
        let filesystem_root = catalog_install_step!(
            $disposition, $pending, filesystem_root,
            open("/", OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty()),
            ProductionSourceProviderCatalogInstallErrorV1::State("filesystem root")
        );
        let root = catalog_install_root!($disposition, $pending, filesystem_root);
        let relative = Path::new(STATE_ROOT).strip_prefix("/")
            .map_err(|_| ProductionSourceProviderCatalogInstallErrorV1::State("fixed path"))?;
        let resolved = catalog_install_step!(
            $disposition, $pending, resolved,
            root.resolve(relative, ResolveOptions { no_mount_crossing: false, require_directory: true }),
            ProductionSourceProviderCatalogInstallErrorV1::State("directory")
        );
        let path_stat = catalog_install_step!(
            $disposition, $pending, path_stat, fstat(resolved.as_fd()),
            ProductionSourceProviderCatalogInstallErrorV1::State("directory metadata")
        );
        if !valid_state_directory(&path_stat) {
            return Err(ProductionSourceProviderCatalogInstallErrorV1::State("directory protection"));
        }
        let directory = catalog_install_step!(
            $disposition, $pending, directory,
            openat(resolved.as_fd(), ".", OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty()),
            ProductionSourceProviderCatalogInstallErrorV1::State("readable directory")
        );
        let readable_stat = catalog_install_step!(
            $disposition, $pending, readable_stat, fstat(&directory),
            ProductionSourceProviderCatalogInstallErrorV1::State("readable metadata")
        );
        if path_stat.st_dev != readable_stat.st_dev
            || path_stat.st_ino != readable_stat.st_ino
            || !valid_state_directory(&readable_stat)
        {
            return Err(ProductionSourceProviderCatalogInstallErrorV1::State("directory changed"));
        }
        catalog_install_state_complete!($disposition, directory)
    }};
}

fn open_private_state_directory()
-> Result<std::os::fd::OwnedFd, ProductionSourceProviderCatalogInstallErrorV1> {
    open_catalog_state_recipe!(Legacy, unused)
}

fn valid_state_directory(stat: &Stat) -> bool {
    FileType::from_raw_mode(stat.st_mode) == FileType::Directory
        && stat.st_uid == 0
        && stat.st_mode & 0o7777 == 0o700
}

macro_rules! catalog_install_existing {
    (Legacy, $pending:ident, $directory:ident, $name:ident) => {
        openat($directory, $name, OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty())
    };
    (Selected, $pending:ident, $directory:ident, $name:ident) => {{
        $pending.existing = Some(openat($directory, $name, OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty()));
        match $pending.existing.as_ref() {
            Some(result) => result.as_ref(),
            None => return Err(ProductionSourceProviderCatalogInstallErrorV1::State("existing custody")),
        }
    }};
}

macro_rules! catalog_install_missing {
    (Legacy, $error:ident) => { $error == rustix::io::Errno::NOENT };
    (Selected, $error:ident) => { *$error == rustix::io::Errno::NOENT };
}

macro_rules! catalog_install_nonce {
    (Legacy, $pending:ident) => { [0; 16] };
    (Selected, $pending:ident) => { &mut $pending.nonce };
}

macro_rules! catalog_install_nonce_count {
    (Legacy, $count:ident) => { $count };
    (Selected, $count:ident) => { *$count };
}

macro_rules! catalog_install_nonce_progress {
    (Legacy, $pending:ident, $filled:ident) => {};
    (Selected, $pending:ident, $filled:ident) => { $pending.filled = $filled; };
}

macro_rules! catalog_install_temporary_name {
    (Legacy, $pending:ident, $name:ident) => { format!(".{}-", $name) };
    (Selected, $pending:ident, $name:ident) => {{
        $pending.temporary_name = Some(format!(".{}-", $name));
        match $pending.temporary_name.as_mut() {
            Some(name) => name,
            None => return Err(ProductionSourceProviderCatalogInstallErrorV1::Publication("temporary name custody")),
        }
    }};
}

macro_rules! catalog_install_nonce_iter {
    (Legacy, $nonce:ident) => { $nonce.into_iter() };
    (Selected, $nonce:ident) => { $nonce.iter().copied() };
}

macro_rules! catalog_install_cleanup {
    (Legacy, $pending:ident, $result:ident, $directory:ident, $name:ident) => {
        if $result.is_err() {
            let _ = unlinkat($directory, $name.as_str(), AtFlags::empty());
        }
    };
    (Selected, $pending:ident, $result:ident, $directory:ident, $name:ident) => {
        // A failed selected invocation retains its real file/name/debt. It must
        // not erase an ambiguous rename or retry publication behind that cut.
    };
}

macro_rules! catalog_install_written_attempt {
    (Legacy, $body:block) => { (|| $body)() };
    (Selected, $body:block) => { $body };
}

macro_rules! catalog_install_written_metadata {
    (Legacy, $pending:ident, $file:ident) => {};
    (Selected, $pending:ident, $file:ident) => {
        catalog_install_step!(
            Selected, $pending, published_stat, fstat($file.as_fd()),
            ProductionSourceProviderCatalogInstallErrorV1::Publication("published metadata")
        );
    };
}

macro_rules! install_catalog_file_recipe {
    ($directory:ident, $name:ident, $bytes:ident, $uid:ident, $disposition:ident, $pending:ident) => {{
        if $bytes.is_empty() || $bytes.len() > MAXIMUM_CATALOG_ROWS_BYTES {
            return Err(ProductionSourceProviderCatalogInstallErrorV1::Credential("publication length"));
        }
        match catalog_install_existing!($disposition, $pending, $directory, $name) {
            Ok(existing) => {
                let stat = catalog_install_step!(
                    $disposition, $pending, existing_stat, fstat(&existing),
                    ProductionSourceProviderCatalogInstallErrorV1::State("existing metadata")
                );
                if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
                    || stat.st_uid != $uid || stat.st_nlink != 1 || stat.st_mode & 0o7777 != 0o600
                {
                    return Err(ProductionSourceProviderCatalogInstallErrorV1::State("existing publication protection"));
                }
            }
            Err(error) if catalog_install_missing!($disposition, error) => {}
            Err(_) => return Err(ProductionSourceProviderCatalogInstallErrorV1::State("existing publication")),
        }

        let mut nonce = catalog_install_nonce!($disposition, $pending);
        let mut filled = 0;
        while filled < nonce.len() {
            let count = catalog_install_step!(
                $disposition, $pending, nonce_result,
                getrandom(&mut nonce[filled..], GetRandomFlags::empty()),
                ProductionSourceProviderCatalogInstallErrorV1::Publication("nonce")
            );
            let count = catalog_install_nonce_count!($disposition, count);
            if count == 0 {
                return Err(ProductionSourceProviderCatalogInstallErrorV1::Publication("nonce short read"));
            }
            filled += count;
            catalog_install_nonce_progress!($disposition, $pending, filled);
        }
        let mut temporary_name = catalog_install_temporary_name!($disposition, $pending, $name);
        for octet in catalog_install_nonce_iter!($disposition, nonce) {
            catalog_install_step!(
                $disposition, $pending, nonce_format, write!(&mut temporary_name, "{octet:02x}"),
                ProductionSourceProviderCatalogInstallErrorV1::Publication("nonce format")
            );
        }
        let descriptor = catalog_install_step!(
            $disposition, $pending, descriptor,
            openat($directory, temporary_name.as_str(), OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::from_raw_mode(0o600)),
            ProductionSourceProviderCatalogInstallErrorV1::Publication("temporary file")
        );
        let result = catalog_install_written_attempt!($disposition, {
            catalog_install_step!(
                $disposition, $pending, mode_result, fchmod(&descriptor, Mode::from_raw_mode(0o600)),
                ProductionSourceProviderCatalogInstallErrorV1::Publication("file mode")
            );
            let mut file = catalog_install_file!($disposition, $pending, descriptor);
            catalog_install_step!(
                $disposition, $pending, write_result, file.write_all($bytes),
                ProductionSourceProviderCatalogInstallErrorV1::Publication("write")
            );
            let stat = catalog_install_step!(
                $disposition, $pending, written_stat, fstat(file.as_fd()),
                ProductionSourceProviderCatalogInstallErrorV1::Publication("file metadata")
            );
            if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
                || stat.st_uid != $uid || stat.st_nlink != 1
                || stat.st_mode & 0o7777 != 0o600 || stat.st_size != $bytes.len() as i64
            {
                return Err(ProductionSourceProviderCatalogInstallErrorV1::Publication("temporary file changed"));
            }
            catalog_install_step!(
                $disposition, $pending, file_sync, file.sync_all(),
                ProductionSourceProviderCatalogInstallErrorV1::Publication("file sync")
            );
            catalog_install_step!(
                $disposition, $pending, rename_result,
                renameat($directory, temporary_name.as_str(), $directory, $name),
                ProductionSourceProviderCatalogInstallErrorV1::Publication("rename")
            );
            catalog_install_step!(
                $disposition, $pending, directory_sync, fsync($directory),
                ProductionSourceProviderCatalogInstallErrorV1::Publication("directory sync")
            );
            catalog_install_written_metadata!($disposition, $pending, file);
            Ok::<(), ProductionSourceProviderCatalogInstallErrorV1>(())
        });
        catalog_install_cleanup!($disposition, $pending, result, $directory, temporary_name);
        result
    }};
}

fn install_in_directory(
    directory: std::os::fd::BorrowedFd<'_>,
    name: &str,
    bytes: &[u8],
    expected_uid: u32,
) -> Result<(), ProductionSourceProviderCatalogInstallErrorV1> {
    install_catalog_file_recipe!(directory, name, bytes, expected_uid, Legacy, unused)
}

#[derive(Default)]
struct SelectedCredentialReadV1 {
    directory_role: SelectedCatalogCredentialDirectoryV1,
    directory_name: Option<std::ffi::OsString>,
    directory: Option<Result<std::os::fd::OwnedFd, rustix::io::Errno>>,
    directory_stat: Option<Result<Stat, rustix::io::Errno>>,
    descriptor: Option<Result<std::os::fd::OwnedFd, rustix::io::Errno>>,
    before: Option<Result<Stat, rustix::io::Errno>>,
    file: Option<File>,
    bytes: Vec<u8>,
    read_result: Option<std::io::Result<()>>,
    trailing: [u8; 1],
    tail_result: Option<std::io::Result<usize>>,
    after: Option<Result<Stat, rustix::io::Errno>>,
    named_descriptor: Option<Result<std::os::fd::OwnedFd, rustix::io::Errno>>,
    named_stat: Option<Result<Stat, rustix::io::Errno>>,
    named_directory: Option<Result<std::os::fd::OwnedFd, rustix::io::Errno>>,
    named_directory_stat: Option<Result<Stat, rustix::io::Errno>>,
    final_named_directory: Option<Result<std::os::fd::OwnedFd, rustix::io::Errno>>,
    final_named_directory_stat: Option<Result<Stat, rustix::io::Errno>>,
    final_named_descriptor: Option<Result<std::os::fd::OwnedFd, rustix::io::Errno>>,
    final_named_stat: Option<Result<Stat, rustix::io::Errno>>,
    final_directory_stat: Option<Result<Stat, rustix::io::Errno>>,
    repeat_directory: Option<Result<Stat, rustix::io::Errno>>,
    repeat_before: Option<Result<Stat, rustix::io::Errno>>,
    repeat_after: Option<Result<Stat, rustix::io::Errno>>,
    rewind: Option<std::io::Result<u64>>,
    repeat_bytes: Vec<u8>,
    repeat_read: Option<std::io::Result<()>>,
    repeat_tail: Option<std::io::Result<usize>>,
    repeat_trailing: [u8; 1],
}

#[derive(Default)]
enum SelectedCatalogCredentialDirectoryV1 {
    #[default]
    Source,
    Mount,
}

impl SelectedCatalogCredentialDirectoryV1 {
    fn path(&self) -> &'static str {
        match self {
            Self::Source => "/run/credentials/aos-source-providerd.service",
            Self::Mount => "/run/credentials/aos-sandbox-mountd.service",
        }
    }
}

/// Retains only the fixed, nonauthorizing catalog DATA delivered to Mount.
/// The selected opening owns this reader before either read can return.
pub(crate) struct SelectedMountCatalogCredentialsV1 {
    publication: SelectedCredentialReadV1,
    manifest: SelectedCredentialReadV1,
    first_failure: Option<ProductionSourceProviderCatalogInstallErrorV1>,
    attempted: bool,
    current: bool,
}

impl Default for SelectedMountCatalogCredentialsV1 {
    fn default() -> Self {
        Self {
            publication: SelectedCredentialReadV1 {
                directory_role: SelectedCatalogCredentialDirectoryV1::Mount,
                ..SelectedCredentialReadV1::default()
            },
            manifest: SelectedCredentialReadV1 {
                directory_role: SelectedCatalogCredentialDirectoryV1::Mount,
                ..SelectedCredentialReadV1::default()
            },
            first_failure: None,
            attempted: false,
            current: false,
        }
    }
}

impl SelectedMountCatalogCredentialsV1 {
    pub(crate) fn read_once(&mut self) -> bool {
        if self.attempted {
            return false;
        }
        self.attempted = true;
        let result = (|| {
            let name = CREDENTIAL_NAME;
            let maximum = PUBLICATION_BYTES;
            let pending = &mut self.publication;
            read_systemd_catalog_recipe!(name, maximum, Selected, pending)?;
            self.publication.recheck_mount_credential(name, maximum)?;

            let name = MANIFEST_CREDENTIAL_NAME;
            let maximum = MAXIMUM_CATALOG_ROWS_BYTES;
            let pending = &mut self.manifest;
            read_systemd_catalog_recipe!(name, maximum, Selected, pending)?;
            self.manifest.recheck_mount_credential(name, maximum)?;
            self.validate_pair()
        })();
        self.finish(result)
    }

    fn validate_pair(&self) -> Result<(), ProductionSourceProviderCatalogInstallErrorV1> {
        let (generation, namespace, digest) = catalog_rows_head(&self.manifest.bytes).ok_or(
            ProductionSourceProviderCatalogInstallErrorV1::Credential("Mount catalog rows are noncanonical"),
        )?;
        if !publication_matches_rows(&self.publication.bytes, generation, namespace, digest) {
            return Err(ProductionSourceProviderCatalogInstallErrorV1::Credential("Mount catalog pair differs"));
        }
        Ok(())
    }

    pub(crate) fn recheck(&mut self) -> bool {
        if !self.current { return false; }
        self.current = false;
        let result = (|| {
            self.publication.recheck_mount_credential(CREDENTIAL_NAME, PUBLICATION_BYTES)?;
            self.manifest.recheck_mount_credential(MANIFEST_CREDENTIAL_NAME, MAXIMUM_CATALOG_ROWS_BYTES)?;
            self.validate_pair()
        })();
        self.finish(result)
    }

    fn finish(&mut self, result: Result<(), ProductionSourceProviderCatalogInstallErrorV1>) -> bool {
        match result {
            Ok(()) => { self.current = true; true }
            Err(cause) => {
                if self.first_failure.is_none() { self.first_failure = Some(cause); }
                false
            }
        }
    }

    pub(crate) fn pair(&self) -> Option<(&[u8], &[u8])> {
        self.current.then_some((&self.publication.bytes, &self.manifest.bytes))
    }

    pub(crate) fn failure(&self) -> Option<SelectedSourceProviderCatalogFailureRefV1<'_>> {
        self.publication.failure().or_else(|| self.manifest.failure()).or_else(|| {
            self.first_failure.as_ref().map(SelectedSourceProviderCatalogFailureRefV1::Install)
        })
    }
}

#[derive(Default)]
struct SelectedCatalogStateV1 {
    filesystem_root: Option<Result<std::os::fd::OwnedFd, rustix::io::Errno>>,
    root_duplicate: Option<Result<std::os::fd::OwnedFd, rustix::io::Errno>>,
    root: Option<aos_sandbox_linux::Result<BeneathRoot>>,
    resolved: Option<aos_sandbox_linux::Result<aos_sandbox_linux::path::ResolvedPath>>,
    path_stat: Option<Result<Stat, rustix::io::Errno>>,
    directory: Option<Result<std::os::fd::OwnedFd, rustix::io::Errno>>,
    readable_stat: Option<Result<Stat, rustix::io::Errno>>,
    after: Option<Result<Stat, rustix::io::Errno>>,
}

#[derive(Default)]
struct SelectedCatalogWriteV1 {
    existing: Option<Result<std::os::fd::OwnedFd, rustix::io::Errno>>,
    existing_stat: Option<Result<Stat, rustix::io::Errno>>,
    nonce: [u8; 16],
    filled: usize,
    nonce_result: Option<Result<usize, rustix::io::Errno>>,
    temporary_name: Option<String>,
    nonce_format: Option<Result<(), std::fmt::Error>>,
    descriptor: Option<Result<std::os::fd::OwnedFd, rustix::io::Errno>>,
    mode_result: Option<Result<(), rustix::io::Errno>>,
    file: Option<File>,
    write_result: Option<std::io::Result<()>>,
    written_stat: Option<Result<Stat, rustix::io::Errno>>,
    file_sync: Option<std::io::Result<()>>,
    rename_result: Option<Result<(), rustix::io::Errno>>,
    directory_sync: Option<Result<(), rustix::io::Errno>>,
    published_stat: Option<Result<Stat, rustix::io::Errno>>,
}

/// Lends a selected installer's actual retained cause without copying it.
pub enum SelectedSourceProviderCatalogFailureRefV1<'owner> {
    /// The selected opening or a later original-custody bookend failed.
    Security(&'owner SourceProviderSecurityError),
    /// A returned syscall result retains the actual kernel cause.
    Kernel(&'owner rustix::io::Errno),
    /// The same consuming path validator returned this retained error.
    Path(&'owner aos_sandbox_linux::Error),
    /// A read, write, seek or file-sync result retains this I/O cause.
    Io(&'owner std::io::Error),
    /// Formatting the bounded temporary basename failed.
    Format(&'owner std::fmt::Error),
    /// The fixed install recipe rejected DATA or original slot association.
    Install(&'owner ProductionSourceProviderCatalogInstallErrorV1),
}

impl core::fmt::Debug for SelectedSourceProviderCatalogFailureRefV1<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("SelectedSourceProviderCatalogFailureRefV1([retained cause])")
    }
}

/// Owns one failed selected catalog invocation and its returned originals.
///
/// Genuine selected custody, delivered files, partial writes, rename results,
/// names and protected readback remain resident. No constructor accepts caller
/// descriptors, role labels, credentials or publication bytes. This is neither
/// a current Source head nor a request, signing, effect or drain capability.
#[must_use = "retain the failed invocation until intentional process termination"]
pub struct SelectedSourceProviderCatalogInstallFailureV1 {
    opening: SelectedSourceProviderCustodyOpeningV1,
    custody: Option<ProtectedProviderCustodyV1>,
    bookends: [Option<Result<RevalidatedProviderConfigurationV1, SourceProviderSecurityError>>; 7],
    publication: SelectedCredentialReadV1,
    manifest: SelectedCredentialReadV1,
    state: SelectedCatalogStateV1,
    manifest_name: Option<String>,
    manifest_write: SelectedCatalogWriteV1,
    publication_write: SelectedCatalogWriteV1,
    readback: crate::production_source_provider::SelectedCatalogPairV1,
    first_failure: Option<ProductionSourceProviderCatalogInstallErrorV1>,
}

impl core::fmt::Debug for SelectedSourceProviderCatalogInstallFailureV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("SelectedSourceProviderCatalogInstallFailureV1([retained original invocation])")
    }
}

impl core::fmt::Display for SelectedSourceProviderCatalogInstallFailureV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("selected Source catalog installation refused; original invocation retained")
    }
}

impl std::error::Error for SelectedSourceProviderCatalogInstallFailureV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.failure().map(|error| match error {
            SelectedSourceProviderCatalogFailureRefV1::Security(error) => error as _,
            SelectedSourceProviderCatalogFailureRefV1::Kernel(error) => error as _,
            SelectedSourceProviderCatalogFailureRefV1::Path(error) => error as _,
            SelectedSourceProviderCatalogFailureRefV1::Io(error) => error as _,
            SelectedSourceProviderCatalogFailureRefV1::Format(error) => error as _,
            SelectedSourceProviderCatalogFailureRefV1::Install(error) => error as _,
        })
    }
}

macro_rules! selected_catalog_native_failure {
    ($pending:ident, $slot:ident, $variant:ident) => {
        if let Some(Err(error)) = $pending.$slot.as_ref() {
            return Some(SelectedSourceProviderCatalogFailureRefV1::$variant(error));
        }
    };
}

impl SelectedCredentialReadV1 {
    fn failure(&self) -> Option<SelectedSourceProviderCatalogFailureRefV1<'_>> {
        let pending = self;
        selected_catalog_native_failure!(pending, directory, Kernel);
        selected_catalog_native_failure!(pending, directory_stat, Kernel);
        selected_catalog_native_failure!(pending, descriptor, Kernel);
        selected_catalog_native_failure!(pending, before, Kernel);
        selected_catalog_native_failure!(pending, read_result, Io);
        selected_catalog_native_failure!(pending, tail_result, Io);
        selected_catalog_native_failure!(pending, after, Kernel);
        selected_catalog_native_failure!(pending, repeat_directory, Kernel);
        selected_catalog_native_failure!(pending, named_directory, Kernel);
        selected_catalog_native_failure!(pending, named_directory_stat, Kernel);
        selected_catalog_native_failure!(pending, named_descriptor, Kernel);
        selected_catalog_native_failure!(pending, named_stat, Kernel);
        selected_catalog_native_failure!(pending, repeat_before, Kernel);
        selected_catalog_native_failure!(pending, rewind, Io);
        selected_catalog_native_failure!(pending, repeat_read, Io);
        selected_catalog_native_failure!(pending, repeat_tail, Io);
        selected_catalog_native_failure!(pending, repeat_after, Kernel);
        selected_catalog_native_failure!(pending, final_named_directory, Kernel);
        selected_catalog_native_failure!(pending, final_named_directory_stat, Kernel);
        selected_catalog_native_failure!(pending, final_named_descriptor, Kernel);
        selected_catalog_native_failure!(pending, final_named_stat, Kernel);
        selected_catalog_native_failure!(pending, final_directory_stat, Kernel);
        None
    }

    fn recheck_mount_credential(
        &mut self,
        name: &'static str,
        maximum: usize,
    ) -> Result<(), ProductionSourceProviderCatalogInstallErrorV1> {
        use std::io::Seek as _;
        if !matches!(self.directory_role, SelectedCatalogCredentialDirectoryV1::Mount) {
            return Err(ProductionSourceProviderCatalogInstallErrorV1::Credential("Mount credential role"));
        }
        let (Some(Ok(directory)), Some(Ok(original_directory)), Some(Ok(original_file)), Some(file)) = (
            self.directory.as_ref(), self.directory_stat.as_ref(), self.before.as_ref(), self.file.as_mut(),
        ) else {
            return Err(ProductionSourceProviderCatalogInstallErrorV1::Credential("Mount original credential custody"));
        };
        self.repeat_directory = Some(fstat(directory));
        self.named_directory = Some(open(
            self.directory_role.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ));
        let Some(Ok(named_directory)) = self.named_directory.as_ref() else {
            return Err(ProductionSourceProviderCatalogInstallErrorV1::Credential("Mount credential directory name"));
        };
        self.named_directory_stat = Some(fstat(named_directory));
        self.named_descriptor = Some(openat(
            directory, name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ));
        let Some(Ok(named)) = self.named_descriptor.as_ref() else {
            return Err(ProductionSourceProviderCatalogInstallErrorV1::Credential("Mount credential name"));
        };
        self.named_stat = Some(fstat(named));
        self.repeat_before = Some(fstat(file.as_fd()));
        let (Some(Ok(directory_now)), Some(Ok(directory_named_now)), Some(Ok(named_now)), Some(Ok(file_now))) = (
            self.repeat_directory.as_ref(), self.named_directory_stat.as_ref(),
            self.named_stat.as_ref(), self.repeat_before.as_ref(),
        ) else {
            return Err(ProductionSourceProviderCatalogInstallErrorV1::Credential("Mount credential metadata"));
        };
        if !same_stable_metadata(original_directory, directory_now)
            || !same_stable_metadata(original_directory, directory_named_now)
            || !same_stable_metadata(original_file, named_now)
            || !same_stable_metadata(original_file, file_now)
            || !valid_credential(file_now, maximum)
        {
            return Err(ProductionSourceProviderCatalogInstallErrorV1::Credential("Mount credential changed"));
        }
        self.rewind = Some(file.seek(std::io::SeekFrom::Start(0)));
        if !matches!(self.rewind, Some(Ok(0))) {
            return Err(ProductionSourceProviderCatalogInstallErrorV1::Credential("Mount credential rewind"));
        }
        self.repeat_bytes.resize(self.bytes.len(), 0);
        self.repeat_read = Some(file.read_exact(&mut self.repeat_bytes));
        if !matches!(self.repeat_read, Some(Ok(()))) {
            return Err(ProductionSourceProviderCatalogInstallErrorV1::Credential("Mount credential reread"));
        }
        self.repeat_tail = Some(file.read(&mut self.repeat_trailing));
        if !matches!(self.repeat_tail, Some(Ok(0))) {
            return Err(ProductionSourceProviderCatalogInstallErrorV1::Credential("Mount credential reread tail"));
        }
        self.repeat_after = Some(fstat(file.as_fd()));
        self.final_named_directory = Some(open(
            self.directory_role.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ));
        let Some(Ok(final_directory)) = self.final_named_directory.as_ref() else {
            return Err(ProductionSourceProviderCatalogInstallErrorV1::Credential("Mount final credential directory name"));
        };
        self.final_named_directory_stat = Some(fstat(final_directory));
        self.final_named_descriptor = Some(openat(
            directory, name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ));
        let Some(Ok(final_named)) = self.final_named_descriptor.as_ref() else {
            return Err(ProductionSourceProviderCatalogInstallErrorV1::Credential("Mount final credential name"));
        };
        self.final_named_stat = Some(fstat(final_named));
        self.final_directory_stat = Some(fstat(directory));
        if self.repeat_bytes != self.bytes
            || !matches!(self.repeat_after.as_ref(), Some(Ok(after)) if same_stable_metadata(original_file, after))
            || !matches!(self.final_named_stat.as_ref(), Some(Ok(after)) if same_stable_metadata(original_file, after))
            || !matches!(self.final_named_directory_stat.as_ref(), Some(Ok(after)) if same_stable_metadata(original_directory, after))
            || !matches!(self.final_directory_stat.as_ref(), Some(Ok(after)) if same_stable_metadata(original_directory, after))
        {
            return Err(ProductionSourceProviderCatalogInstallErrorV1::Credential("Mount credential reread changed"));
        }
        Ok(())
    }
}

impl SelectedCatalogWriteV1 {
    fn failure(&self) -> Option<SelectedSourceProviderCatalogFailureRefV1<'_>> {
        if let Some(Err(error)) = self.existing.as_ref() {
            if *error != rustix::io::Errno::NOENT {
                return Some(SelectedSourceProviderCatalogFailureRefV1::Kernel(error));
            }
        }
        let pending = self;
        selected_catalog_native_failure!(pending, existing_stat, Kernel);
        selected_catalog_native_failure!(pending, nonce_result, Kernel);
        selected_catalog_native_failure!(pending, nonce_format, Format);
        selected_catalog_native_failure!(pending, descriptor, Kernel);
        selected_catalog_native_failure!(pending, mode_result, Kernel);
        selected_catalog_native_failure!(pending, write_result, Io);
        selected_catalog_native_failure!(pending, written_stat, Kernel);
        selected_catalog_native_failure!(pending, file_sync, Io);
        selected_catalog_native_failure!(pending, rename_result, Kernel);
        selected_catalog_native_failure!(pending, directory_sync, Kernel);
        selected_catalog_native_failure!(pending, published_stat, Kernel);
        None
    }
}

impl SelectedSourceProviderCatalogInstallFailureV1 {
    /// Lends the original native or recipe failure without observing or retrying.
    #[must_use]
    pub fn failure(&self) -> Option<SelectedSourceProviderCatalogFailureRefV1<'_>> {
        if let Some(error) = self.opening.failure() {
            return Some(SelectedSourceProviderCatalogFailureRefV1::Security(error));
        }
        for result in &self.bookends {
            if let Some(Err(error)) = result {
                return Some(SelectedSourceProviderCatalogFailureRefV1::Security(error));
            }
        }
        if let Some(error) = self.publication.failure().or_else(|| self.manifest.failure()) {
            return Some(error);
        }
        let pending = &self.state;
        selected_catalog_native_failure!(pending, filesystem_root, Kernel);
        selected_catalog_native_failure!(pending, root_duplicate, Kernel);
        selected_catalog_native_failure!(pending, root, Path);
        selected_catalog_native_failure!(pending, resolved, Path);
        selected_catalog_native_failure!(pending, path_stat, Kernel);
        selected_catalog_native_failure!(pending, directory, Kernel);
        selected_catalog_native_failure!(pending, readable_stat, Kernel);
        selected_catalog_native_failure!(pending, after, Kernel);
        if let Some(error) = self.manifest_write.failure().or_else(|| self.publication_write.failure()) {
            return Some(error);
        }
        if let Some(error) = self.readback.failure() {
            use crate::production_source_provider::CatalogReadFailureRefV1;
            return Some(match error {
                CatalogReadFailureRefV1::Kernel(error) => SelectedSourceProviderCatalogFailureRefV1::Kernel(error),
                CatalogReadFailureRefV1::Path(error) => SelectedSourceProviderCatalogFailureRefV1::Path(error),
                CatalogReadFailureRefV1::Read(error) => SelectedSourceProviderCatalogFailureRefV1::Io(error),
            });
        }
        self.first_failure
            .as_ref()
            .map(SelectedSourceProviderCatalogFailureRefV1::Install)
    }

    fn new() -> Self {
        Self {
            opening: ProtectedProviderCustodyV1::begin_fixed_selected_mount_source(),
            custody: None,
            bookends: [const { None }; 7],
            publication: SelectedCredentialReadV1::default(),
            manifest: SelectedCredentialReadV1::default(),
            state: SelectedCatalogStateV1::default(),
            manifest_name: None,
            manifest_write: SelectedCatalogWriteV1::default(),
            publication_write: SelectedCatalogWriteV1::default(),
            readback: crate::production_source_provider::SelectedCatalogPairV1::default(),
            first_failure: None,
        }
    }

    fn bookend(
        &mut self,
        index: usize,
    ) -> Result<(), ProductionSourceProviderCatalogInstallErrorV1> {
        let slot = self.bookends.get_mut(index).ok_or(
            ProductionSourceProviderCatalogInstallErrorV1::State("selected bookend custody"),
        )?;
        if slot.is_some() {
            return Err(ProductionSourceProviderCatalogInstallErrorV1::State("selected bookend already used"));
        }
        let custody = self.custody.as_mut().ok_or(
            ProductionSourceProviderCatalogInstallErrorV1::State("selected authority custody"),
        )?;
        *slot = Some(custody.revalidated_configuration());
        if !matches!(slot.as_ref(), Some(Ok(_))) {
            return Err(ProductionSourceProviderCatalogInstallErrorV1::State("selected authority changed"));
        }
        Ok(())
    }

    fn install(&mut self) -> Result<(), ProductionSourceProviderCatalogInstallErrorV1> {
        if !rustix::process::getuid().is_root() || !rustix::process::geteuid().is_root() {
            return Err(ProductionSourceProviderCatalogInstallErrorV1::Identity);
        }
        if self.opening.open_once().is_err() {
            return Err(ProductionSourceProviderCatalogInstallErrorV1::State("selected authority opening"));
        }
        self.custody = self.opening.take_provider_custody();
        self.bookend(0)?;

        let name = CREDENTIAL_NAME;
        let maximum = PUBLICATION_BYTES;
        let pending = &mut self.publication;
        read_systemd_catalog_recipe!(name, maximum, Selected, pending)?;
        let name = MANIFEST_CREDENTIAL_NAME;
        let maximum = MAXIMUM_CATALOG_ROWS_BYTES;
        let pending = &mut self.manifest;
        read_systemd_catalog_recipe!(name, maximum, Selected, pending)?;
        let (generation, namespace, digest) = catalog_rows_head(&self.manifest.bytes).ok_or(
            ProductionSourceProviderCatalogInstallErrorV1::Credential("catalog rows are noncanonical"),
        )?;
        if !publication_matches_rows(&self.publication.bytes, generation, namespace, digest) {
            return Err(ProductionSourceProviderCatalogInstallErrorV1::Credential("manifest does not match publication head"));
        }
        let pending = &mut self.state;
        open_catalog_state_recipe!(Selected, pending)?;
        self.manifest_name = Some(manifest_filename(digest));
        self.bookend(1)?;

        let directory = match self.state.directory.as_ref() {
            Some(Ok(directory)) => directory.as_fd(),
            _ => return Err(ProductionSourceProviderCatalogInstallErrorV1::State("selected directory custody")),
        };
        let name = self.manifest_name.as_deref().ok_or(
            ProductionSourceProviderCatalogInstallErrorV1::State("selected manifest name custody"),
        )?;
        let bytes = self.manifest.bytes.as_slice();
        let expected_uid = 0;
        let pending = &mut self.manifest_write;
        install_catalog_file_recipe!(directory, name, bytes, expected_uid, Selected, pending)?;
        self.bookend(2)?;
        self.bookend(3)?;

        let directory = match self.state.directory.as_ref() {
            Some(Ok(directory)) => directory.as_fd(),
            _ => return Err(ProductionSourceProviderCatalogInstallErrorV1::State("selected directory custody")),
        };
        let name = CREDENTIAL_NAME;
        let bytes = self.publication.bytes.as_slice();
        let pending = &mut self.publication_write;
        install_catalog_file_recipe!(directory, name, bytes, expected_uid, Selected, pending)?;
        self.bookend(4)?;
        self.bookend(5)?;

        let directory = match self.state.directory.as_ref() {
            Some(Ok(directory)) => directory,
            _ => return Err(ProductionSourceProviderCatalogInstallErrorV1::State("selected directory custody")),
        };
        self.state.after = Some(fstat(directory));
        let before = match self.state.readable_stat.as_ref() {
            Some(Ok(metadata)) => metadata,
            _ => return Err(ProductionSourceProviderCatalogInstallErrorV1::State("selected directory metadata custody")),
        };
        let after = match self.state.after.as_ref() {
            Some(Ok(metadata))
                if valid_state_directory(metadata)
                    && before.st_dev == metadata.st_dev
                    && before.st_ino == metadata.st_ino
                    && before.st_mode == metadata.st_mode
                    && before.st_gid == metadata.st_gid => metadata,
            _ => return Err(ProductionSourceProviderCatalogInstallErrorV1::State("selected directory changed")),
        };
        self.readback.read_once().map_err(|_| {
            ProductionSourceProviderCatalogInstallErrorV1::State("selected protected pair readback")
        })?;
        if !self.readback.matches_original_bytes(&self.publication.bytes, &self.manifest.bytes) {
            return Err(ProductionSourceProviderCatalogInstallErrorV1::State("selected protected pair changed"));
        }
        let publication = match self.publication_write.published_stat.as_ref() {
            Some(Ok(metadata)) => metadata,
            _ => return Err(ProductionSourceProviderCatalogInstallErrorV1::State("selected publication metadata custody")),
        };
        let manifest = match self.manifest_write.published_stat.as_ref() {
            Some(Ok(metadata)) => metadata,
            _ => return Err(ProductionSourceProviderCatalogInstallErrorV1::State("selected manifest metadata custody")),
        };
        if !self.readback.matches_written_originals(after, publication, manifest) {
            return Err(ProductionSourceProviderCatalogInstallErrorV1::State("selected written originals changed"));
        }
        self.bookend(6)
    }
}

/// Installs the fixed catalog pair under the genuine selected Source task.
///
/// Selected role admission precedes credential/state reads. The same recipes
/// perform bounded reads and manifest-before-publication writes, with returned
/// originals parked before postchecks. A failed write does not remove its
/// temporary file or retry an ambiguous rename. Success is nonauthorizing DATA
/// only. Lower never-returned prefixes and allocation/funding remain exclusions;
/// no universal unwind, physical settlement or descriptor-drain claim follows.
///
/// # Errors
///
/// Returns the whole failed invocation for identity, selected custody, fixed
/// credential, pair, durable write, rename, readback or final bookend rejection.
pub fn install_fixed_selected_source_provider_catalog_credential()
-> Result<(), SelectedSourceProviderCatalogInstallFailureV1> {
    let mut original = SelectedSourceProviderCatalogInstallFailureV1::new();
    if let Err(error) = original.install() {
        original.first_failure = Some(error);
        return Err(original);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_core::ObjectDigest;
    use aos_sandbox_source_provider_protocol::{
        ProviderCatalogRowV1, ProviderHeldSnapshotRowV1, StorageLiveExportSelectorV1,
        ZfsHeldSnapshotProofV1,
    };

    fn manifest() -> ProviderCatalogManifestV1 {
        let selector = StorageLiveExportSelectorV1::new(
            [1; 16],
            1,
            [2; 32],
            ObjectDigest::from_bytes([3; 32]),
        )
        .unwrap();
        let row = ProviderCatalogRowV1::new(
            ObjectDigest::from_bytes([4; 32]),
            [5; 32],
            1,
            ObjectDigest::from_bytes([6; 32]),
            1,
            ObjectDigest::from_bytes([7; 32]),
            selector,
        )
        .unwrap();
        ProviderCatalogManifestV1::new(2, ObjectDigest::from_bytes([8; 32]), vec![row]).unwrap()
    }

    fn held_catalog() -> ProviderHeldSnapshotCatalogV1 {
        let snapshot = ZfsHeldSnapshotProofV1::new(
            [9; 32],
            10,
            11,
            12,
            13,
            [14; 16],
            15,
            ObjectDigest::from_bytes([16; 32]),
            ObjectDigest::from_bytes([17; 32]),
            ObjectDigest::from_bytes([18; 32]),
        )
        .unwrap();
        let row = ProviderHeldSnapshotRowV1::new(
            ObjectDigest::from_bytes([4; 32]),
            [5; 32],
            1,
            ObjectDigest::from_bytes([6; 32]),
            1,
            ObjectDigest::from_bytes([7; 32]),
            snapshot,
        )
        .unwrap();
        ProviderHeldSnapshotCatalogV1::new(2, ObjectDigest::from_bytes([8; 32]), vec![row]).unwrap()
    }

    #[test]
    fn native_rows_install_under_exact_publication_head() {
        let catalog = held_catalog();
        let bytes = catalog.to_canonical_bytes();
        let (generation, namespace, digest) = catalog_rows_head(&bytes).unwrap();
        assert_eq!(generation, catalog.generation());
        assert_eq!(namespace, catalog.namespace_digest());
        assert_eq!(digest, catalog.digest());

        let mut publication = vec![0; PUBLICATION_BYTES];
        publication[0..8].copy_from_slice(b"AOSPCP01");
        publication[72..104].copy_from_slice(namespace.as_bytes());
        publication[104..112].copy_from_slice(&generation.to_be_bytes());
        publication[112..144].copy_from_slice(digest.as_bytes());
        assert!(publication_matches_rows(
            &publication,
            generation,
            namespace,
            digest
        ));

        publication[112] ^= 1;
        assert!(!publication_matches_rows(
            &publication,
            generation,
            namespace,
            digest
        ));
        let mut malformed = bytes;
        malformed[0] ^= 1;
        assert!(catalog_rows_head(&malformed).is_none());
    }

    #[test]
    fn manifest_pair_rejects_downgrade_and_fork_before_installation() {
        let manifest = manifest();
        let mut publication = vec![0; PUBLICATION_BYTES];
        publication[0..8].copy_from_slice(b"AOSPCP01");
        publication[72..104].copy_from_slice(manifest.namespace_digest().as_bytes());
        publication[104..112].copy_from_slice(&manifest.generation().to_be_bytes());
        publication[112..144].copy_from_slice(manifest.digest().as_bytes());
        assert!(publication_matches_rows(
            &publication,
            manifest.generation(),
            manifest.namespace_digest(),
            manifest.digest(),
        ));

        publication[104..112].copy_from_slice(&1_u64.to_be_bytes());
        assert!(!publication_matches_rows(
            &publication,
            manifest.generation(),
            manifest.namespace_digest(),
            manifest.digest(),
        ));
        publication[104..112].copy_from_slice(&manifest.generation().to_be_bytes());
        publication[112] ^= 1;
        assert!(!publication_matches_rows(
            &publication,
            manifest.generation(),
            manifest.namespace_digest(),
            manifest.digest(),
        ));
    }

    #[test]
    fn atomic_installer_replaces_exact_private_publication() {
        let temporary = tempfile::tempdir().expect("temporary state directory");
        let directory = open(
            temporary.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("open state directory");
        let uid = rustix::process::geteuid().as_raw();
        install_in_directory(
            directory.as_fd(),
            CREDENTIAL_NAME,
            &[1; PUBLICATION_BYTES],
            uid,
        )
        .expect("first publication");
        install_in_directory(
            directory.as_fd(),
            CREDENTIAL_NAME,
            &[2; PUBLICATION_BYTES],
            uid,
        )
        .expect("replacement publication");

        let installed = std::fs::read(temporary.path().join(CREDENTIAL_NAME))
            .expect("read installed publication");
        assert_eq!(installed, [2; PUBLICATION_BYTES]);
        assert_eq!(
            std::fs::read_dir(temporary.path())
                .expect("list state")
                .count(),
            1
        );
    }

    #[test]
    fn atomic_installer_rejects_length_and_existing_symlink() {
        let temporary = tempfile::tempdir().expect("temporary state directory");
        let directory = open(
            temporary.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("open state directory");
        let uid = rustix::process::geteuid().as_raw();
        assert!(install_in_directory(directory.as_fd(), CREDENTIAL_NAME, &[], uid).is_err());
        std::os::unix::fs::symlink("elsewhere", temporary.path().join(CREDENTIAL_NAME))
            .expect("place unsafe existing entry");
        assert!(
            install_in_directory(
                directory.as_fd(),
                CREDENTIAL_NAME,
                &[0; PUBLICATION_BYTES],
                uid
            )
            .is_err()
        );
    }

    #[test]
    fn atomic_installer_rejects_linked_or_public_existing_file() {
        use std::os::unix::fs::PermissionsExt as _;

        let temporary = tempfile::tempdir().expect("temporary state directory");
        let directory = open(
            temporary.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("open state directory");
        let uid = rustix::process::geteuid().as_raw();
        let publication = temporary.path().join(CREDENTIAL_NAME);
        std::fs::write(&publication, [3; PUBLICATION_BYTES]).expect("existing publication");

        std::fs::set_permissions(&publication, std::fs::Permissions::from_mode(0o644))
            .expect("public mode");
        assert!(
            install_in_directory(
                directory.as_fd(),
                CREDENTIAL_NAME,
                &[4; PUBLICATION_BYTES],
                uid
            )
            .is_err()
        );

        std::fs::set_permissions(&publication, std::fs::Permissions::from_mode(0o600))
            .expect("private mode");
        std::fs::hard_link(&publication, temporary.path().join("linked-publication"))
            .expect("existing hard link");
        assert!(
            install_in_directory(
                directory.as_fd(),
                CREDENTIAL_NAME,
                &[4; PUBLICATION_BYTES],
                uid
            )
            .is_err()
        );
        assert_eq!(
            std::fs::read(publication).expect("unchanged publication"),
            [3; PUBLICATION_BYTES]
        );
    }
}
