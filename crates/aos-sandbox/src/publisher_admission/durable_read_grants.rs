//! Fixed protected current heads for independent publisher read grants.
//!
//! This journal is distinct from publication admission and its catalog. A
//! sealed object remains undisclosed unless a current grant from this owner
//! joins the protected catalog and root at the moment of `OpenForRead`.
//!
//! ```text
//! AOSPRG01 | v1 | predecessor-grant | holder | project | resource |
//! domain-kind | domain-id | policy | generation | state | grant-digest |
//! record-digest
//! ```

use std::collections::BTreeMap;
use std::path::Path;

use aos_sandbox_core::{
    CacheDomainId, ObjectDigest, PrincipalId, ProjectId, ResourceId,
    model::{CacheDomain, CacheDomainKind},
};
use sha2::{Digest as _, Sha256};

use super::read_authority::{ReadAuthorityGrantV1, ReadAuthorityRegistryV1, ReadGrantStateV1};
use crate::journal::{
    Journal, JournalError, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace,
    RecoveryReport,
};

const FIXED_PUBLISHER_ROOT: &str = "/var/lib/aos/sandbox/publisher";
const READ_GRANT_JOURNAL: &str = "read-grants-v1.journal";
const KEY_PREFIX: &[u8] = b"\0aos-publisher-read-grant-v1\0holder\0";
const MAGIC: &[u8; 8] = b"AOSPRG01";
const VERSION: u16 = 1;
const RECORD_DOMAIN: &[u8] = b"aos.sandbox.publisher.durable-read-grant.v1\0";
const RECORD_PREFIX_BYTES: usize = 180;
const RECORD_BYTES: usize = RECORD_PREFIX_BYTES + 32;
const MAXIMUM_GRANTS: usize = 65_536;
const MAXIMUM_RESOLUTION_ATTEMPTS: usize = 8;

/// Reports unsafe or malformed protected read-grant custody.
#[derive(Debug, thiserror::Error)]
pub(super) enum PublisherDurableReadGrantErrorV1 {
    /// The fixed protected journal could not be opened or replayed.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// A current head, predecessor, or capacity is invalid.
    #[error("publisher durable read grant is invalid or stale")]
    Invalid,
}

/// Separates confirmed read-grant durability from an exact unresolved append.
#[must_use = "an unknown read-grant outcome blocks new read authorization"]
enum PublisherReadGrantCommitOutcomeV1 {
    /// Exact durable readback proved the requested current grant.
    Applied(ReadAuthorityGrantV1),
    /// The exact transaction requires protected reopen before any new read.
    OutcomeUnknown(PublisherReadGrantOutcomeUnknownV1),
}

/// Retains the predecessor and successor through ambiguous durability.
#[must_use = "unresolved read-grant custody must be recovered"]
struct PublisherReadGrantOutcomeUnknownV1 {
    transaction: JournalTransaction,
    previous: Option<ReadAuthorityGrantV1>,
    intended: ReadAuthorityGrantV1,
    attempts: usize,
}

/// Classifies an exact protected reopen of a pending read-grant transition.
#[must_use = "read authorization remains closed until the outcome is applied"]
enum PublisherReadGrantRecoveryV1 {
    /// The intended successor is durable and current.
    Applied(ReadAuthorityGrantV1),
    /// The exact predecessor remained current but retry is still ambiguous.
    OutcomeUnknown(PublisherReadGrantOutcomeUnknownV1),
    /// Another head or reused transaction identity conflicts with the intent.
    Conflict(PublisherReadGrantOutcomeUnknownV1),
}

/// Holds the sole fixed journal lock and its validated current grant projection.
pub(super) struct PublisherDurableReadGrantOwnerV1 {
    journal: Option<Journal>,
    heads: BTreeMap<[u8; 16], ReadAuthorityGrantV1>,
    registry: ReadAuthorityRegistryV1,
    unresolved: bool,
}

impl PublisherDurableReadGrantOwnerV1 {
    /// Opens and validates every current grant beneath the fixed publisher root.
    ///
    /// Only committed transactions enter the current projection. A caller
    /// issuing a revocation must retain ambiguous commit custody until its
    /// exact outcome is classified; a discarded uncommitted tail was never an
    /// acknowledged revocation.
    pub(super) fn open_fixed_protected()
    -> Result<(Self, RecoveryReport), PublisherDurableReadGrantErrorV1> {
        let (journal, report) = Journal::open_protected_at(
            Path::new(FIXED_PUBLISHER_ROOT),
            READ_GRANT_JOURNAL,
            read_grant_journal_limits(),
        )?;
        let heads = read_current_heads(&journal)?;
        let registry =
            ReadAuthorityRegistryV1::from_current_heads(MAXIMUM_GRANTS, heads.values().cloned())
                .map_err(|_| PublisherDurableReadGrantErrorV1::Invalid)?;
        Ok((
            Self {
                journal: Some(journal),
                heads,
                registry,
                unresolved: false,
            },
            report,
        ))
    }

    /// Borrows grants only while the fixed journal still matches its opened head.
    pub(super) fn current_registry(
        &self,
    ) -> Result<&ReadAuthorityRegistryV1, PublisherDurableReadGrantErrorV1> {
        if self.unresolved || read_current_heads(self.journal()?)? != self.heads {
            return Err(PublisherDurableReadGrantErrorV1::Invalid);
        }
        Ok(&self.registry)
    }

    /// Commits one successor after a separate protected issuer has been joined.
    ///
    /// This method remains private until that issuer supplies an opaque grant
    /// capability. A public principal, request body, or publication permit
    /// cannot issue a read grant. An unresolved append closes reads until its
    /// exact recovery.
    fn commit_issued_successor(
        &mut self,
        grant: ReadAuthorityGrantV1,
    ) -> Result<PublisherReadGrantCommitOutcomeV1, PublisherDurableReadGrantErrorV1> {
        self.current_registry()?;
        grant
            .validate()
            .map_err(|_| PublisherDurableReadGrantErrorV1::Invalid)?;
        let previous = self.heads.get(grant.holder.as_bytes()).cloned();
        let predecessor = match (&previous, grant.state) {
            (None, ReadGrantStateV1::Active) if grant.generation == 1 => {
                ObjectDigest::from_bytes([0; 32])
            }
            (Some(previous), ReadGrantStateV1::Revoked)
                if previous.state == ReadGrantStateV1::Active
                    && previous.generation == 1
                    && grant.generation == 2
                    && same_scope(previous, &grant) =>
            {
                previous.grant_digest
            }
            _ => return Err(PublisherDurableReadGrantErrorV1::Invalid),
        };
        let bytes = encode_current_head(&grant, predecessor)?;
        let record_digest = digest(&bytes[..RECORD_PREFIX_BYTES]);
        let mut transaction_id = [0_u8; 16];
        transaction_id.copy_from_slice(&record_digest.as_bytes()[..16]);
        if transaction_id == [0; 16] {
            return Err(PublisherDurableReadGrantErrorV1::Invalid);
        }
        let transaction = JournalTransaction::new(
            transaction_id,
            vec![JournalRecord::put(
                RecordNamespace::PublisherAuthority,
                grant_key(grant.holder),
                bytes,
            )],
        )?;
        let pending = PublisherReadGrantOutcomeUnknownV1 {
            transaction,
            previous,
            intended: grant,
            attempts: 0,
        };
        self.unresolved = true;
        match self.journal_mut()?.commit(&pending.transaction) {
            Ok(_) => {
                if self.refresh_to_intended(&pending.intended).is_ok() {
                    self.unresolved = false;
                    Ok(PublisherReadGrantCommitOutcomeV1::Applied(pending.intended))
                } else {
                    Ok(PublisherReadGrantCommitOutcomeV1::OutcomeUnknown(pending))
                }
            }
            Err(_) => Ok(PublisherReadGrantCommitOutcomeV1::OutcomeUnknown(pending)),
        }
    }

    /// Reopens and resolves one exact unknown grant transaction.
    fn recover_outcome_unknown(
        &mut self,
        mut pending: PublisherReadGrantOutcomeUnknownV1,
    ) -> PublisherReadGrantRecoveryV1 {
        while pending.attempts < MAXIMUM_RESOLUTION_ATTEMPTS {
            pending.attempts += 1;
            if self.reopen_fixed().is_err() {
                continue;
            }
            let observed = match self
                .journal()
                .and_then(read_current_heads)
                .map(|heads| heads.get(pending.intended.holder.as_bytes()).cloned())
            {
                Ok(observed) => observed,
                Err(_) => continue,
            };
            if observed.as_ref() == Some(&pending.intended) {
                if self.refresh_to_intended(&pending.intended).is_ok() {
                    self.unresolved = false;
                    return PublisherReadGrantRecoveryV1::Applied(pending.intended);
                }
                continue;
            }
            if observed != pending.previous {
                return PublisherReadGrantRecoveryV1::Conflict(pending);
            }
            match self.journal_mut().and_then(|journal| {
                journal.commit(&pending.transaction)?;
                Ok(())
            }) {
                Ok(()) => {
                    if self.refresh_to_intended(&pending.intended).is_ok() {
                        self.unresolved = false;
                        return PublisherReadGrantRecoveryV1::Applied(pending.intended);
                    }
                }
                Err(PublisherDurableReadGrantErrorV1::Journal(
                    JournalError::DuplicateTransaction,
                )) => {
                    return PublisherReadGrantRecoveryV1::Conflict(pending);
                }
                Err(_) => {}
            }
        }
        PublisherReadGrantRecoveryV1::OutcomeUnknown(pending)
    }

    fn refresh_to_intended(
        &mut self,
        intended: &ReadAuthorityGrantV1,
    ) -> Result<(), PublisherDurableReadGrantErrorV1> {
        let heads = read_current_heads(self.journal()?)?;
        if heads.get(intended.holder.as_bytes()) != Some(intended) {
            return Err(PublisherDurableReadGrantErrorV1::Invalid);
        }
        let registry =
            ReadAuthorityRegistryV1::from_current_heads(MAXIMUM_GRANTS, heads.values().cloned())
                .map_err(|_| PublisherDurableReadGrantErrorV1::Invalid)?;
        self.heads = heads;
        self.registry = registry;
        Ok(())
    }

    fn reopen_fixed(&mut self) -> Result<(), PublisherDurableReadGrantErrorV1> {
        drop(self.journal.take());
        let (journal, _) = Journal::open_protected_at(
            Path::new(FIXED_PUBLISHER_ROOT),
            READ_GRANT_JOURNAL,
            read_grant_journal_limits(),
        )?;
        self.journal = Some(journal);
        Ok(())
    }

    fn journal(&self) -> Result<&Journal, PublisherDurableReadGrantErrorV1> {
        self.journal
            .as_ref()
            .ok_or(PublisherDurableReadGrantErrorV1::Invalid)
    }

    fn journal_mut(&mut self) -> Result<&mut Journal, PublisherDurableReadGrantErrorV1> {
        self.journal
            .as_mut()
            .ok_or(PublisherDurableReadGrantErrorV1::Invalid)
    }
}

fn grant_key(holder: PrincipalId) -> Vec<u8> {
    [KEY_PREFIX, holder.as_bytes()].concat()
}

fn same_scope(previous: &ReadAuthorityGrantV1, next: &ReadAuthorityGrantV1) -> bool {
    previous.holder == next.holder
        && previous.project == next.project
        && previous.resource == next.resource
        && previous.domain == next.domain
        && previous.policy_digest == next.policy_digest
}

fn encode_current_head(
    grant: &ReadAuthorityGrantV1,
    predecessor: ObjectDigest,
) -> Result<Vec<u8>, PublisherDurableReadGrantErrorV1> {
    let mut bytes = Vec::with_capacity(RECORD_BYTES);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.extend_from_slice(predecessor.as_bytes());
    bytes.extend_from_slice(grant.holder.as_bytes());
    bytes.extend_from_slice(grant.project.as_bytes());
    bytes.extend_from_slice(grant.resource.as_bytes());
    bytes.push(2);
    bytes.extend_from_slice(grant.domain.domain_id().as_bytes());
    bytes.extend_from_slice(grant.policy_digest.as_bytes());
    bytes.extend_from_slice(&grant.generation.to_be_bytes());
    bytes.push(match grant.state {
        ReadGrantStateV1::Active => 1,
        ReadGrantStateV1::Revoked => 2,
    });
    bytes.extend_from_slice(grant.grant_digest.as_bytes());
    if bytes.len() != RECORD_PREFIX_BYTES {
        return Err(PublisherDurableReadGrantErrorV1::Invalid);
    }
    bytes.extend_from_slice(digest(&bytes).as_bytes());
    if decode_current_head(&bytes)? != *grant {
        return Err(PublisherDurableReadGrantErrorV1::Invalid);
    }
    Ok(bytes)
}

fn read_current_heads(
    journal: &Journal,
) -> Result<BTreeMap<[u8; 16], ReadAuthorityGrantV1>, PublisherDurableReadGrantErrorV1> {
    let mut heads = BTreeMap::new();
    for (namespace, key, bytes) in journal.all_records() {
        if namespace != RecordNamespace::PublisherAuthority
            || !key.starts_with(KEY_PREFIX)
            || key.len() != KEY_PREFIX.len() + 16
        {
            return Err(PublisherDurableReadGrantErrorV1::Invalid);
        }
        let grant = decode_current_head(bytes)?;
        if &key[KEY_PREFIX.len()..] != grant.holder.as_bytes()
            || heads.insert(*grant.holder.as_bytes(), grant).is_some()
            || heads.len() > MAXIMUM_GRANTS
        {
            return Err(PublisherDurableReadGrantErrorV1::Invalid);
        }
    }
    Ok(heads)
}

fn decode_current_head(
    bytes: &[u8],
) -> Result<ReadAuthorityGrantV1, PublisherDurableReadGrantErrorV1> {
    if bytes.len() != RECORD_BYTES
        || &bytes[..8] != MAGIC
        || bytes[8..10] != VERSION.to_be_bytes()
        || bytes[90] != 2
        || digest(&bytes[..RECORD_PREFIX_BYTES]).as_bytes() != &bytes[RECORD_PREFIX_BYTES..]
    {
        return Err(PublisherDurableReadGrantErrorV1::Invalid);
    }
    let predecessor = ObjectDigest::from_bytes(exact(&bytes[10..42])?);
    let holder = PrincipalId::from_bytes(exact(&bytes[42..58])?);
    let project = ProjectId::from_bytes(exact(&bytes[58..74])?);
    let resource = ResourceId::from_bytes(exact(&bytes[74..90])?);
    let domain = CacheDomain::new(
        CacheDomainKind::Project,
        CacheDomainId::from_bytes(exact(&bytes[91..107])?),
    );
    let policy_digest = ObjectDigest::from_bytes(exact(&bytes[107..139])?);
    let generation = u64::from_be_bytes(exact(&bytes[139..147])?);
    let state = match bytes[147] {
        1 => ReadGrantStateV1::Active,
        2 => ReadGrantStateV1::Revoked,
        _ => return Err(PublisherDurableReadGrantErrorV1::Invalid),
    };
    let grant = ReadAuthorityGrantV1 {
        holder,
        project,
        resource,
        domain,
        policy_digest,
        generation,
        state,
        grant_digest: ObjectDigest::from_bytes(exact(&bytes[148..180])?),
    };
    grant
        .validate()
        .map_err(|_| PublisherDurableReadGrantErrorV1::Invalid)?;

    let expected_predecessor = match state {
        ReadGrantStateV1::Active if generation == 1 => ObjectDigest::from_bytes([0; 32]),
        ReadGrantStateV1::Revoked if generation == 2 => {
            ReadAuthorityGrantV1::active(holder, project, resource, domain, policy_digest, 1)
                .map_err(|_| PublisherDurableReadGrantErrorV1::Invalid)?
                .grant_digest
        }
        _ => return Err(PublisherDurableReadGrantErrorV1::Invalid),
    };
    if predecessor != expected_predecessor {
        return Err(PublisherDurableReadGrantErrorV1::Invalid);
    }
    Ok(grant)
}

fn digest(bytes: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(RECORD_DOMAIN)
            .chain_update((bytes.len() as u64).to_be_bytes())
            .chain_update(bytes)
            .finalize()
            .into(),
    )
}

fn exact<const N: usize>(bytes: &[u8]) -> Result<[u8; N], PublisherDurableReadGrantErrorV1> {
    bytes
        .try_into()
        .map_err(|_| PublisherDurableReadGrantErrorV1::Invalid)
}

const fn read_grant_journal_limits() -> JournalLimits {
    JournalLimits {
        maximum_journal_bytes: 128 * 1024 * 1024,
        maximum_record_bytes: 1024,
        maximum_key_bytes: 128,
        maximum_records_per_transaction: 2,
        maximum_transaction_bytes: 4096,
        maximum_transactions: 1_000_000,
        maximum_materialized_bytes: 32 * 1024 * 1024,
        maximum_materialized_records: MAXIMUM_GRANTS,
    }
}
