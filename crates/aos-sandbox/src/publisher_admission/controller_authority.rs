//! Retained protected controller authority for fixed publisher bootstrap.
//!
//! The controller provisions this fixed, root-owned journal out of band. This
//! dormant adapter accepts no caller-selected path or configuration. It checks
//! one canonical immutable configuration record and its singular current head,
//! retains the journal lock, and mints a one-shot grant only while performing
//! clean publisher bootstrap.
//!
//! ```text
//! config:  AOSPCA01 | v1 | generation | predecessor | config-len | config | digest
//! current: AOSPCH01 | v1 | generation | config-digest | digest
//! ```

use std::path::Path;

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use super::fixed_owner::{
    PublisherFixedInstallerV1, PublisherFixedProtectedOpenReportV1,
    PublisherFixedProtectedOwnerErrorV1, PublisherFixedProtectedOwnerV1, config_equal,
    decode_config, encode_config,
};
use super::service::PublisherDomainServiceConfigV1;
use crate::journal::{Journal, JournalError, JournalLimits, RecordNamespace, RecoveryReport};

const CONTROLLER_ROOT: &str = "/var/lib/aos/controller/publisher-authority";
const CONTROLLER_JOURNAL: &str = "publisher-bootstrap-v1.journal";
const CURRENT_KEY: &[u8] = b"\0aos-publisher-controller-authority-v1\0current";
const RECORD_KEY_PREFIX: &[u8] = b"\0aos-publisher-controller-authority-v1\0record\0";
const RECORD_MAGIC: &[u8; 8] = b"AOSPCA01";
const CURRENT_MAGIC: &[u8; 8] = b"AOSPCH01";
const VERSION: u16 = 1;
const RECORD_DOMAIN: &[u8] = b"aos.sandbox.publisher.controller-authority.record.v1\0";
const CURRENT_DOMAIN: &[u8] = b"aos.sandbox.publisher.controller-authority.current.v1\0";

/// Reports protected controller-authority failures.
#[derive(Debug, thiserror::Error)]
pub enum PublisherFixedControllerAuthorityErrorV1 {
    /// The fixed protected source journal could not be opened or replayed.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// The source record, current head, or canonical configuration is invalid.
    #[error("fixed publisher controller authority is invalid or stale")]
    Authority,
    /// Clean publisher installation or target reopen failed.
    #[error(transparent)]
    Publisher(#[from] PublisherFixedProtectedOwnerErrorV1),
}

/// Reports a clean fixed publisher bootstrap and protected target reopen.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublisherFixedBootstrapReportV1 {
    /// Reports initial target authority-journal creation.
    pub installed_authority: RecoveryReport,
    /// Reports the immediately reopened protected publisher journals.
    pub opened: PublisherFixedProtectedOpenReportV1,
}

/// Retains the fixed protected controller journal and its exact current head.
pub struct PublisherFixedControllerAuthorityOwnerV1 {
    journal: Journal,
    generation: u64,
    record_digest: ObjectDigest,
    current_digest: ObjectDigest,
    config: PublisherDomainServiceConfigV1,
}

/// Carries one current controller configuration directly into the installer.
#[must_use = "the controller grant must be consumed by fixed publisher bootstrap"]
pub(super) struct PublisherFixedControllerGrantV1 {
    config: PublisherDomainServiceConfigV1,
    _source_record_digest: ObjectDigest,
    _source_current_digest: ObjectDigest,
}

impl PublisherFixedControllerGrantV1 {
    fn issue_from_retained_owner(
        config: PublisherDomainServiceConfigV1,
        source_record_digest: ObjectDigest,
        source_current_digest: ObjectDigest,
    ) -> Result<Self, PublisherFixedControllerAuthorityErrorV1> {
        if source_record_digest.as_bytes() == &[0; 32]
            || source_current_digest.as_bytes() == &[0; 32]
        {
            return Err(PublisherFixedControllerAuthorityErrorV1::Authority);
        }
        Ok(Self {
            config,
            _source_record_digest: source_record_digest,
            _source_current_digest: source_current_digest,
        })
    }

    pub(super) const fn into_config(self) -> PublisherDomainServiceConfigV1 {
        self.config
    }
}

impl PublisherFixedControllerAuthorityOwnerV1 {
    /// Opens and retains the internally fixed protected controller authority.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherFixedControllerAuthorityErrorV1`] unless the journal
    /// contains exactly one canonical configuration and its matching current head.
    pub fn open_fixed_protected()
    -> Result<(Self, RecoveryReport), PublisherFixedControllerAuthorityErrorV1> {
        let (journal, report) = Journal::open_protected_at(
            Path::new(CONTROLLER_ROOT),
            CONTROLLER_JOURNAL,
            controller_journal_limits(),
        )?;
        let authenticated = read_current(&journal)?;
        Ok((
            Self {
                journal,
                generation: authenticated.generation,
                record_digest: authenticated.record_digest,
                current_digest: authenticated.current_digest,
                config: authenticated.config,
            },
            report,
        ))
    }

    /// Bootstraps and reopens the fixed publisher from current controller custody.
    ///
    /// This is the only clean-bootstrap callsite for the private installer. It
    /// rereads the protected current head immediately before issuing the
    /// one-shot grant; callers cannot obtain either value separately.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherFixedControllerAuthorityErrorV1`] if source
    /// currentness changed, the target is not clean, or target reopen fails.
    pub fn bootstrap_fixed_publisher(
        &mut self,
    ) -> Result<
        (
            PublisherFixedProtectedOwnerV1,
            PublisherFixedBootstrapReportV1,
        ),
        PublisherFixedControllerAuthorityErrorV1,
    > {
        let current = read_current(&self.journal)?;
        if current.generation != self.generation
            || current.record_digest != self.record_digest
            || current.current_digest != self.current_digest
            || !config_equal(current.config, self.config)
        {
            return Err(PublisherFixedControllerAuthorityErrorV1::Authority);
        }
        let grant = PublisherFixedControllerGrantV1::issue_from_retained_owner(
            current.config,
            current.record_digest,
            current.current_digest,
        )?;
        let installed_authority =
            PublisherFixedInstallerV1::new().install_clean_controller(grant)?;
        let (owner, opened) = PublisherFixedProtectedOwnerV1::open_fixed_protected()?;
        Ok((
            owner,
            PublisherFixedBootstrapReportV1 {
                installed_authority,
                opened,
            },
        ))
    }
}

struct AuthenticatedControllerRecordV1 {
    generation: u64,
    record_digest: ObjectDigest,
    current_digest: ObjectDigest,
    config: PublisherDomainServiceConfigV1,
}

fn read_current(
    journal: &Journal,
) -> Result<AuthenticatedControllerRecordV1, PublisherFixedControllerAuthorityErrorV1> {
    let mut current = None;
    let mut record = None;
    for (namespace, key, bytes) in journal.all_records() {
        if namespace != RecordNamespace::PublisherAuthority {
            return Err(PublisherFixedControllerAuthorityErrorV1::Authority);
        }
        if key == CURRENT_KEY {
            if current.replace(decode_current(bytes)?).is_some() {
                return Err(PublisherFixedControllerAuthorityErrorV1::Authority);
            }
        } else if key.starts_with(RECORD_KEY_PREFIX) && key.len() == RECORD_KEY_PREFIX.len() + 32 {
            if record.replace((key, bytes)).is_some() {
                return Err(PublisherFixedControllerAuthorityErrorV1::Authority);
            }
        } else {
            return Err(PublisherFixedControllerAuthorityErrorV1::Authority);
        }
    }
    let (generation, record_digest, current_digest) =
        current.ok_or(PublisherFixedControllerAuthorityErrorV1::Authority)?;
    let (key, bytes) = record.ok_or(PublisherFixedControllerAuthorityErrorV1::Authority)?;
    if &key[RECORD_KEY_PREFIX.len()..] != record_digest.as_bytes() {
        return Err(PublisherFixedControllerAuthorityErrorV1::Authority);
    }
    let (record_generation, config) = decode_record(bytes, record_digest)?;
    if record_generation != generation {
        return Err(PublisherFixedControllerAuthorityErrorV1::Authority);
    }
    Ok(AuthenticatedControllerRecordV1 {
        generation,
        record_digest,
        current_digest,
        config,
    })
}

fn decode_record(
    bytes: &[u8],
    expected_digest: ObjectDigest,
) -> Result<(u64, PublisherDomainServiceConfigV1), PublisherFixedControllerAuthorityErrorV1> {
    const PREFIX: usize = 8 + 2 + 8 + 32 + 2;
    if bytes.len() < PREFIX + 32
        || &bytes[..8] != RECORD_MAGIC
        || bytes[8..10] != VERSION.to_be_bytes()
    {
        return Err(PublisherFixedControllerAuthorityErrorV1::Authority);
    }
    let generation = u64::from_be_bytes(exact(&bytes[10..18])?);
    let predecessor = ObjectDigest::from_bytes(exact(&bytes[18..50])?);
    let config_len = usize::from(u16::from_be_bytes(exact(&bytes[50..52])?));
    let end = PREFIX
        .checked_add(config_len)
        .ok_or(PublisherFixedControllerAuthorityErrorV1::Authority)?;
    if generation == 0
        || (generation == 1) != (predecessor.as_bytes() == &[0; 32])
        || bytes.len() != end + 32
    {
        return Err(PublisherFixedControllerAuthorityErrorV1::Authority);
    }
    let retained = ObjectDigest::from_bytes(exact(&bytes[end..])?);
    let derived = digest(RECORD_DOMAIN, &bytes[..end]);
    let (config, _) = decode_config(&bytes[PREFIX..end])?;
    if retained != expected_digest
        || retained != derived
        || encode_config(config)? != bytes[PREFIX..end]
    {
        return Err(PublisherFixedControllerAuthorityErrorV1::Authority);
    }
    Ok((generation, config))
}

fn decode_current(
    bytes: &[u8],
) -> Result<(u64, ObjectDigest, ObjectDigest), PublisherFixedControllerAuthorityErrorV1> {
    if bytes.len() != 82 || &bytes[..8] != CURRENT_MAGIC || bytes[8..10] != VERSION.to_be_bytes() {
        return Err(PublisherFixedControllerAuthorityErrorV1::Authority);
    }
    let generation = u64::from_be_bytes(exact(&bytes[10..18])?);
    let record_digest = ObjectDigest::from_bytes(exact(&bytes[18..50])?);
    let retained = ObjectDigest::from_bytes(exact(&bytes[50..82])?);
    let derived = digest(CURRENT_DOMAIN, &bytes[..50]);
    if generation == 0 || record_digest.as_bytes() == &[0; 32] || retained != derived {
        return Err(PublisherFixedControllerAuthorityErrorV1::Authority);
    }
    Ok((generation, record_digest, retained))
}

fn digest(domain: &[u8], bytes: &[u8]) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn exact<const N: usize>(
    bytes: &[u8],
) -> Result<[u8; N], PublisherFixedControllerAuthorityErrorV1> {
    bytes
        .try_into()
        .map_err(|_| PublisherFixedControllerAuthorityErrorV1::Authority)
}

const fn controller_journal_limits() -> JournalLimits {
    JournalLimits {
        maximum_journal_bytes: 1024 * 1024,
        maximum_record_bytes: 4096,
        maximum_key_bytes: 128,
        maximum_records_per_transaction: 2,
        maximum_transaction_bytes: 16 * 1024,
        maximum_transactions: 65_536,
        maximum_materialized_bytes: 8192,
        maximum_materialized_records: 2,
    }
}
