//! Fixed SourceProvider activation, catalog, and closed source ingress.
//!
//! The production listener admits only one named systemd descriptor at one
//! pathname. Each accepted child retains kernel record subjects and enters the
//! existing fixed provider owner, which must finish its protected handshake
//! before signing a current-head response, inspecting a selected LocalLive
//! plan through Storage, or admitting holder Inventory. A protected native
//! catalog can select an Applying attempt, but returns only Unavailable;
//! backend effects remain closed.

use std::fs::File;
use std::io::Read as _;
use std::os::fd::{AsFd as _, OwnedFd};
use std::path::Path;
use std::time::Duration;

use aos_sandbox_linux::inherited_fd::claim_systemd_activation_descriptor_range;
use aos_sandbox_linux::path::{BeneathRoot, ResolveOptions};
use aos_sandbox_linux::seqpacket::{RecordSubjectListener, SeqpacketError};
use aos_sandbox_source_provider::{
    FixedProviderCatalogProgressV1, FixedProviderIngressProgressV1, FixedProviderOpenReportV1,
    FixedProviderOwnerStatusV1, FixedProviderOwnerV1,
    FixedProviderOriginalStorageOfferProgressV5, ProviderLedgerError,
};
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::fs::{FileType, Mode, OFlags, Stat, fstat, open, openat};
use rustix::io::fcntl_dupfd_cloexec;

use crate::ProductionBrokerSessionActivationErrorV1;
use crate::production_activation::{
    activation_names, remaining_duration, validate_activation_process,
};
use crate::production_source_provider_catalog::{
    MAXIMUM_CATALOG_ROWS_BYTES, catalog_rows_head, same_stable_metadata,
};

const LISTENER_NAME: &str = "aos-source-provider";
const LISTENER_PATH: &str = "/run/aos/source-provider/control.sock";
const STATE_ROOT: &str = "/var/lib/aos/source-provider";
const CATALOG_PUBLICATION: &str = "current-catalog-publication";
const CATALOG_PUBLICATION_BYTES: usize = 520;

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
            $disposition, $pending, read_result, file.read_exact(&mut bytes), "publication bytes"
        );
        let mut trailing = catalog_read_tail!($disposition, $pending);
        let tail_count = catalog_read_step!(
            $disposition, $pending, tail_result, file.read(&mut trailing), "publication tail"
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
    digest: aos_sandbox_core::ObjectDigest,
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


mod selected;
pub(crate) use selected::{CatalogReadFailureRefV1, SelectedCatalogPairV1};
pub use selected::{
    ProductionSelectedSourceProviderFailureRefV1, ProductionSelectedSourceProviderOriginalV1,
};

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
    /// The fixed owner requires migration provenance before serving requests.
    #[error("SourceProvider migration requires authenticated external provenance")]
    MigrationRequired,
}

/// Owns the exact source-provider listener after single-threaded FD adoption.
///
/// Accepted channels are only candidates. The returned fixed owner must
/// complete its protected peer handshake and catalog/journal verification;
/// this type never grants backend or source-effect response authority.
///
/// Deployment supplies one systemd listener named `aos-source-provider` at
/// `/run/aos/source-provider/control.sock` and a root-owned, mode-0700 state
/// directory at `/var/lib/aos/source-provider`. The 520-byte
/// `current-catalog-publication` file and content-addressed row manifest there
/// must be root-owned, mode-0600, regular, and singly linked. The signed
/// publication must match the protected provider journal; pathnames alone do
/// not authorize a session or selected resource.
#[must_use = "retain the fixed listener while admitting provider sessions"]
pub struct ProductionSourceProviderIngressV1 {
    listener: RecordSubjectListener,
}

impl ProductionSourceProviderIngressV1 {
    /// Claims the sole named systemd listener before other descriptors are opened.
    ///
    /// # Safety
    ///
    /// The caller must be the single-threaded startup owner of FD 3. No other
    /// owner, thread, signal handler, or concurrent operation may open, close,
    /// duplicate, or replace it until this call returns.
    ///
    /// # Errors
    ///
    /// Rejects a wrong PID, descriptor count or name, socket type, identity
    /// option, or bound pathname. The claimed descriptor closes on rejection.
    pub unsafe fn adopt_systemd() -> Result<Self, ProductionSourceProviderIngressErrorV1> {
        validate_activation_process(1)?;
        let names = activation_names(1)?;
        validate_listener_names(&names)?;

        // SAFETY: forwarded from the public startup contract after validating
        // the complete one-descriptor activation envelope.
        let descriptors = unsafe { claim_systemd_activation_descriptor_range(0, 1) }
            .map_err(|_| ProductionBrokerSessionActivationErrorV1::Kernel)?
            .into_descriptors();
        let descriptor = descriptors.into_iter().next().ok_or(
            ProductionBrokerSessionActivationErrorV1::Activation(
                "SourceProvider listener descriptor is absent",
            ),
        )?;
        Self::from_owned_listener(descriptor)
    }

    /// Accepts a candidate and opens fixed provider custody and journal state.
    ///
    /// The 520-byte catalog file is a protected locator, not independent
    /// authority. [`FixedProviderOwnerV1::advance_handshake`] verifies its
    /// signature and exact journal head after the peer handshake completes.
    ///
    /// # Errors
    ///
    /// Rejects an expired deadline, changed listener, invalid child identity
    /// options, missing protected catalog file, or fixed-owner admission error.
    pub fn accept_pending_owner(
        &mut self,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<
        (FixedProviderOwnerV1, FixedProviderOpenReportV1),
        ProductionSourceProviderIngressErrorV1,
    > {
        let socket = self.accept_fixed_candidate(deadline_boottime_nanoseconds)?;
        let catalog = read_protected_catalog_publication()?;
        FixedProviderOwnerV1::open_fixed(socket, &catalog).map_err(Into::into)
    }

    /// Parks one genuine fixed-listener candidate in the selected opening.
    ///
    /// No protected catalog or authority file is read here. The selected
    /// opening first validates its actual retained local task role.
    ///
    /// # Errors
    ///
    /// Rejects an expired deadline, changed listener or lower acceptance error.
    /// A lower call that never returns a socket remains a custody exclusion.
    pub fn accept_selected_pending_owner(
        &mut self,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<ProductionSelectedSourceProviderOriginalV1, ProductionSourceProviderIngressErrorV1> {
        let socket = self.accept_fixed_candidate(deadline_boottime_nanoseconds)?;
        Ok(ProductionSelectedSourceProviderOriginalV1::new(socket, deadline_boottime_nanoseconds))
    }

    fn accept_fixed_candidate(
        &self,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket, ProductionSourceProviderIngressErrorV1> {
        loop {
            self.wait_until_ready(deadline_boottime_nanoseconds)?;
            self.listener.validate_current()?;
            match self.listener.accept_descriptor_subject() {
                Ok(socket) => return Ok(socket),
                Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => continue,
                Err(error) => return Err(error.into()),
            }
        }
    }

    /// Completes peer authentication and fixed-journal admission by a deadline.
    ///
    /// The security owner keeps the carrier private. A bounded pause between
    /// nonblocking handshake steps avoids exporting a raw socket descriptor to
    /// a poller. A legacy graph requiring migration provenance remains closed.
    ///
    /// # Errors
    ///
    /// Returns an error on deadline expiry, peer or custody failure, catalog
    /// mismatch, journal failure, or migration requiring external provenance.
    pub fn accept_authenticated_owner(
        &mut self,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<
        (FixedProviderOwnerV1, FixedProviderOpenReportV1),
        ProductionSourceProviderIngressErrorV1,
    > {
        let (mut owner, report) = self.accept_pending_owner(deadline_boottime_nanoseconds)?;
        loop {
            let remaining = remaining_duration(deadline_boottime_nanoseconds)?;
            match owner.advance_handshake()? {
                FixedProviderOwnerStatusV1::Ready => return Ok((owner, report)),
                FixedProviderOwnerStatusV1::HandshakePending => {
                    std::thread::sleep(Duration::from_nanos(remaining.min(2_000_000)));
                }
                FixedProviderOwnerStatusV1::HeldReadOnly => {
                    return Err(ProviderLedgerError::InvalidTransition(
                        "held profile cannot serve authenticated effects",
                    )
                    .into());
                }
                FixedProviderOwnerStatusV1::MigrationRequired
                | FixedProviderOwnerStatusV1::MigrationRecoveryRequired => {
                    return Err(ProductionSourceProviderIngressErrorV1::MigrationRequired);
                }
            }
        }
    }

    /// Advances only the catalog-currentness control path on a retained owner.
    ///
    /// The publication is freshly read through the protected fixed path for
    /// each step. The owner verifies its signature and current journal head
    /// before signing or sending a response; effect requests remain rejected.
    ///
    /// # Errors
    ///
    /// Rejects publication drift, stale custody or journal, malformed or
    /// replayed control, peer death, and carrier failure.
    pub fn advance_catalog_currentness(
        &self,
        owner: &mut FixedProviderOwnerV1,
    ) -> Result<FixedProviderCatalogProgressV1, ProductionSourceProviderIngressErrorV1> {
        self.listener.validate_current()?;
        let publication = read_protected_catalog_publication()?;
        owner
            .advance_catalog_currentness(&publication)
            .map_err(Into::into)
    }

    /// Advances catalog control or receives one Acquire or Inventory request.
    ///
    /// The fixed owner brands a source request only after the retained
    /// authenticated carrier receives its exact descriptor-free packet.
    ///
    /// # Errors
    ///
    /// Rejects a retired listener, changed publication, invalid query or
    /// source frame, or lost protected session custody.
    pub fn advance_authenticated_ingress(
        &self,
        owner: &mut FixedProviderOwnerV1,
    ) -> Result<FixedProviderIngressProgressV1, ProductionSourceProviderIngressErrorV1> {
        if owner.original_native_ingress_closed() {
            return Err(
                ProviderLedgerError::InvalidTransition("original ingress is closed").into(),
            );
        }
        let result = (|| {
            self.listener.validate_current()?;
            if owner.original_native_pair_pending() {
                let (publication, rows) = self.read_current_catalog_manifest()?;
                owner
                    .advance_original_native_pair(&publication, &rows)
                    .map_err(Into::into)
            } else {
                let publication = read_protected_catalog_publication()?;
                owner
                    .advance_authenticated_ingress(&publication)
                    .map_err(Into::into)
            }
        })();
        if result.is_err() {
            owner.close_original_native_ingress_after_failure();
        }
        result
    }

    /// Advances the same retained original pair through StoragePrepared only.
    ///
    /// The protected locator and rows are comparison DATA. Only the genuine
    /// owner's retained pair, first clock, selected owner and original writer
    /// can admit this lane. It does not complete, deliver SourceRoot or relay.
    ///
    /// # Errors
    ///
    /// Rejects listener/catalog drift. The caller must retain the returned
    /// first cause with the permanently closed original owner.
    pub fn advance_original_storage_offer(
        &self,
        owner: &mut FixedProviderOwnerV1,
    ) -> Result<FixedProviderOriginalStorageOfferProgressV5, ProductionSourceProviderIngressErrorV1> {
        let result = (|| {
            self.listener.validate_current()?;
            let (publication, rows) = self.read_current_catalog_manifest()?;
            let progress = owner.advance_original_storage_offer_v5(&publication, &rows);
            self.listener.validate_current()?;
            Ok(progress)
        })();
        if result.is_err() {
            owner.close_original_storage_offer_after_failure_v5();
        }
        result
    }

    /// Reads the content-addressed row catalog under the protected fixed root.
    ///
    /// The returned bytes are nonauthorizing. The fixed owner must compare the
    /// canonical digest and row against its signed publication and journal
    /// snapshot before constructing any Provider-to-Storage plan.
    ///
    /// # Errors
    ///
    /// Rejects missing, replaced, public, malformed, or forked catalog rows.
    pub fn read_current_catalog_manifest(
        &self,
    ) -> Result<(Vec<u8>, Vec<u8>), ProductionSourceProviderIngressErrorV1> {
        self.listener.validate_current()?;
        let publication = read_protected_catalog_publication()?;
        let digest =
            aos_sandbox_core::ObjectDigest::from_bytes(publication[112..144].try_into().map_err(
                |_| ProductionSourceProviderIngressErrorV1::Catalog("publication digest"),
            )?);
        let name = crate::production_source_provider_catalog::manifest_filename(digest);
        let manifest_bytes = read_protected_catalog_file(&name, MAXIMUM_CATALOG_ROWS_BYTES)?;
        validate_catalog_pair_data(&publication, &manifest_bytes, digest)?;
        Ok((publication, manifest_bytes))
    }

    fn from_owned_listener(
        descriptor: OwnedFd,
    ) -> Result<Self, ProductionSourceProviderIngressErrorV1> {
        let listener = RecordSubjectListener::from_owned(descriptor)?;
        listener.require_local_filesystem_path(Path::new(LISTENER_PATH))?;
        Ok(Self { listener })
    }

    fn wait_until_ready(
        &self,
        deadline: u64,
    ) -> Result<(), ProductionSourceProviderIngressErrorV1> {
        let remaining = remaining_duration(deadline)?;
        let timeout = Timespec {
            tv_sec: i64::try_from(remaining / 1_000_000_000)
                .map_err(|_| ProductionBrokerSessionActivationErrorV1::Deadline)?,
            tv_nsec: i64::try_from(remaining % 1_000_000_000)
                .map_err(|_| ProductionBrokerSessionActivationErrorV1::Deadline)?,
        };
        let mut poll_fd = [PollFd::from_borrowed_fd(
            self.listener.as_fd(),
            PollFlags::IN,
        )];
        match poll(&mut poll_fd, Some(&timeout)) {
            Ok(0) => Err(ProductionBrokerSessionActivationErrorV1::Deadline.into()),
            Ok(_) | Err(rustix::io::Errno::INTR) => Ok(()),
            Err(_) => Err(ProductionBrokerSessionActivationErrorV1::Kernel.into()),
        }
    }
}

fn validate_listener_names(
    names: &[String],
) -> Result<(), ProductionBrokerSessionActivationErrorV1> {
    if names.len() != 1 || names[0] != LISTENER_NAME {
        return Err(ProductionBrokerSessionActivationErrorV1::Activation(
            "SourceProvider descriptor name differs from the fixed listener",
        ));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn activation_name_rejects_substitution_and_extra_descriptors() {
        assert!(validate_listener_names(&[LISTENER_NAME.to_owned()]).is_ok());
        assert!(validate_listener_names(&["aos-sandbox-mount".to_owned()]).is_err());
        assert!(validate_listener_names(&[]).is_err());
        assert!(
            validate_listener_names(&[LISTENER_NAME.to_owned(), LISTENER_NAME.to_owned()]).is_err()
        );
    }

    #[test]
    fn foreign_listener_path_is_rejected_before_owner_admission() {
        let temporary = tempfile::tempdir().expect("temporary socket directory");
        let path = temporary.path().join("source-provider.sock");
        let listener = RecordSubjectListener::bind(&path, 1).expect("configured listener");
        assert!(
            listener
                .require_local_filesystem_path(Path::new(LISTENER_PATH))
                .is_err()
        );
    }

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
}
