//! Bounded whole-placement verification for an admitted store graph.
//!
//! Each physical leaf is inventoried under its exclusive administrative
//! fence, but packed reads take the shared lifecycle lock, so placements
//! cannot be read while that fence is held. The fenced inventory is therefore
//! spooled to an anonymous owner-only file in a caller-provided private
//! directory and replayed after the fence is released. Memory stays constant
//! in the number of placements; the logical-byte budget bounds the work.
//!
//! Each spool record has a fixed width and never leaves the process:
//!
//! ```text
//! offset  bytes  field
//!      0      1  object-kind tag
//!      1      4  schema version, big endian
//!      5     32  content digest
//!     37      8  logical length, big endian
//! ```

use std::fs::{File, Permissions};
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use thiserror::Error;

use super::*;

/// Default aggregate logical bytes authenticated by one verification.
pub const DEFAULT_STORE_GRAPH_VERIFY_LOGICAL_BYTES: u64 = 128 * 1024 * 1024 * 1024;

/// Aggregate work limits for one whole-placement verification.
///
/// Placement count is not limited: the fenced inventory is spooled to disk,
/// so memory does not grow with the store. The logical-byte budget bounds the
/// read work an operator commits to before verification starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreGraphVerificationLimits {
    maximum_logical_bytes: u64,
}

impl StoreGraphVerificationLimits {
    /// Default limits shared by store-administration callers.
    pub const DEFAULT: Self = Self::new(DEFAULT_STORE_GRAPH_VERIFY_LOGICAL_BYTES);

    /// Builds limits authenticating at most `maximum_logical_bytes` in total.
    #[must_use]
    pub const fn new(maximum_logical_bytes: u64) -> Self {
        Self {
            maximum_logical_bytes,
        }
    }

    /// Returns the maximum aggregate authenticated logical bytes.
    #[must_use]
    pub const fn maximum_logical_bytes(self) -> u64 {
        self.maximum_logical_bytes
    }
}

impl Default for StoreGraphVerificationLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Aggregate limit exceeded by a verification inventory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreGraphVerificationLimit {
    /// Maximum sum of authenticated logical lengths.
    LogicalBytes,
}

/// Stable evidence for one authenticated physical leaf.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreGraphPhysicalVerification {
    node: StoreNodeId,
    backend: String,
    generation: InventoryGeneration,
    placements: u64,
    logical_bytes: u64,
}

impl StoreGraphPhysicalVerification {
    /// Returns the exact admitted graph node.
    #[must_use]
    pub const fn node(&self) -> &StoreNodeId {
        &self.node
    }

    /// Returns the physical backend identity reproduced by both inventories.
    #[must_use]
    pub fn backend(&self) -> &str {
        &self.backend
    }

    /// Returns the stable inventory generation reproduced after authentication.
    #[must_use]
    pub const fn generation(&self) -> InventoryGeneration {
        self.generation
    }

    /// Returns the exact number of authenticated placements.
    #[must_use]
    pub const fn placements(&self) -> u64 {
        self.placements
    }

    /// Returns the checked sum of authenticated logical lengths.
    #[must_use]
    pub const fn logical_bytes(&self) -> u64 {
        self.logical_bytes
    }
}

/// Terminal evidence for one complete set of per-leaf stable inventories.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreGraphVerificationReport {
    configuration: StoreGraphConfigurationId,
    placements: u64,
    logical_bytes: u64,
    physical: Vec<StoreGraphPhysicalVerification>,
}

impl StoreGraphVerificationReport {
    /// Returns the exact graph configuration whose placements were verified.
    #[must_use]
    pub const fn configuration(&self) -> StoreGraphConfigurationId {
        self.configuration
    }

    /// Returns the aggregate physical placement count.
    #[must_use]
    pub const fn placements(&self) -> u64 {
        self.placements
    }

    /// Returns the aggregate authenticated logical bytes.
    #[must_use]
    pub const fn logical_bytes(&self) -> u64 {
        self.logical_bytes
    }

    /// Returns physical summaries in canonical graph-node order.
    #[must_use]
    pub fn physical(&self) -> &[StoreGraphPhysicalVerification] {
        &self.physical
    }
}

/// Failure to authenticate one complete stable physical store inventory.
#[derive(Debug, Error)]
pub enum StoreGraphVerificationError {
    /// The inventory spool directory could not be inspected.
    #[error("cannot inspect inventory spool directory {}: {source}", path.display())]
    SpoolDirectory {
        /// Caller-provided spool directory.
        path: PathBuf,
        /// Underlying metadata failure.
        #[source]
        source: io::Error,
    },
    /// The inventory spool directory is not an owner-only directory.
    #[error(
        "inventory spool directory {} is not a directory without group or other permissions",
        path.display()
    )]
    InsecureSpoolDirectory {
        /// Caller-provided spool directory.
        path: PathBuf,
    },
    /// A leaf's fenced inventory could not be spooled or replayed.
    #[error("cannot spool the inventory of physical node {node}: {source}")]
    Spool {
        /// Exact admitted physical node.
        node: StoreNodeId,
        /// Underlying spool-file failure.
        #[source]
        source: io::Error,
    },
    /// A physical inventory could not be fenced or completed.
    #[error("cannot inventory physical node {node}: {source}")]
    Inventory {
        /// Exact admitted physical node.
        node: StoreNodeId,
        /// Classified backend failure.
        #[source]
        source: StoreError,
    },
    /// A terminal inventory returned an unexpected backend identity.
    #[error("physical node {node} returned backend identity {actual:?}, expected {expected:?}")]
    BackendIdentityMismatch {
        /// Exact admitted physical node.
        node: StoreNodeId,
        /// Node-bound backend identity expected from the inventory.
        expected: String,
        /// Backend identity returned by the terminal inventory.
        actual: String,
    },
    /// The aggregate operation exceeded one work limit.
    #[error("physical inventory exceeds the verification bound at node {node}: {limit:?}")]
    LimitExceeded {
        /// Node being inventoried when the aggregate limit was exceeded.
        node: StoreNodeId,
        /// Exact limit that was exceeded.
        limit: StoreGraphVerificationLimit,
    },
    /// A placement could not be opened from its exact physical leaf.
    #[error("cannot read physical node {node} object {id}: {source}")]
    Read {
        /// Exact admitted physical node.
        node: StoreNodeId,
        /// Logical object that could not be opened.
        id: ContentId,
        /// Classified backend failure.
        #[source]
        source: StoreError,
    },
    /// An opened handle disagreed with its fenced inventory record.
    #[error(
        "physical node {node} object {id} changed logical length from {inventoried} to {opened}"
    )]
    LogicalLengthChanged {
        /// Exact admitted physical node.
        node: StoreNodeId,
        /// Logical object whose length changed.
        id: ContentId,
        /// Logical length recorded by the fenced inventory.
        inventoried: u64,
        /// Logical length declared by the opened handle.
        opened: u64,
    },
    /// A complete placement stream failed before authenticated EOF.
    #[error("cannot authenticate physical node {node} object {id}: {source}")]
    Authenticate {
        /// Exact admitted physical node.
        node: StoreNodeId,
        /// Logical object that did not authenticate completely.
        id: ContentId,
        /// Deferred stream, length, or digest failure.
        #[source]
        source: StoreError,
    },
    /// The leaf's inventory changed while its objects were authenticated.
    #[error("physical node {node} changed while it was verified")]
    InventoryChanged {
        /// Exact admitted physical node.
        node: StoreNodeId,
        /// Opening inventory generation.
        before: InventoryGeneration,
        /// Closing generation when a terminal inventory was available.
        after: Option<InventoryGeneration>,
    },
}

impl StoreGraphAdmin {
    /// Authenticates every physical placement under a stable per-leaf generation.
    ///
    /// Each leaf is inventoried independently under its exclusive
    /// administrative fence, which spools the inventory to an anonymous
    /// owner-only file in `spool_directory`. The fence is released before the
    /// method streams every spooled placement to authenticated EOF, then
    /// reacquired to reproduce the backend identity, generation, placement
    /// count, and logical-byte total. The logical-byte limit applies to the
    /// aggregate across all leaves; memory does not grow with the placement
    /// count. The report contains only bounded operational summaries and
    /// never discloses placement IDs or deletion authority. A leaf may change
    /// after its closing inventory while a later leaf is verified; the report
    /// does not claim one graph-wide atomic inventory generation.
    ///
    /// `spool_directory` must be a directory without group or other
    /// permissions, because the spool reveals the inventory's object IDs.
    ///
    /// # Errors
    ///
    /// Returns [`StoreGraphVerificationError`] when the spool directory is
    /// missing or not owner-only, a spool file cannot be written or replayed,
    /// a fence or inventory fails, the aggregate work limit is exceeded, a
    /// placement cannot be opened or completely authenticated, its length
    /// differs from inventory, or the terminal inventory basis changes during
    /// verification.
    pub fn verify_physical_inventory(
        &self,
        limits: StoreGraphVerificationLimits,
        spool_directory: &Path,
    ) -> Result<StoreGraphVerificationReport, StoreGraphVerificationError> {
        self.verify_physical_inventory_with_observer(limits, spool_directory, &mut |_| {})
    }

    pub(super) fn verify_physical_inventory_with_observer(
        &self,
        limits: StoreGraphVerificationLimits,
        spool_directory: &Path,
        after_reads: &mut dyn FnMut(&StoreNodeId),
    ) -> Result<StoreGraphVerificationReport, StoreGraphVerificationError> {
        validate_spool_directory(spool_directory)?;

        let mut placements = 0_u64;
        let mut logical_bytes = 0_u64;
        let mut physical = Vec::with_capacity(self.physical.len());

        for (node, authority) in &self.physical {
            let (first, spooled) = spool_fenced_inventory(
                node,
                authority,
                limits,
                spool_directory,
                &mut logical_bytes,
            )?;
            validate_backend_identity(node, &first)?;

            authenticate_spooled_placements(node, authority, spooled)?;
            after_reads(node);

            let second = closing_inventory(node, authority, &first)?;
            validate_backend_identity(node, &second)?;
            if second != first {
                return Err(StoreGraphVerificationError::InventoryChanged {
                    node: node.clone(),
                    before: first.generation(),
                    after: Some(second.generation()),
                });
            }

            placements = placements.checked_add(first.objects()).ok_or_else(|| {
                StoreGraphVerificationError::Inventory {
                    node: node.clone(),
                    source: StoreError::Quota,
                }
            })?;
            physical.push(StoreGraphPhysicalVerification {
                node: node.clone(),
                backend: first.backend().to_owned(),
                generation: first.generation(),
                placements: first.objects(),
                logical_bytes: first.logical_bytes(),
            });
        }

        Ok(StoreGraphVerificationReport {
            configuration: self.configuration,
            placements,
            logical_bytes,
            physical,
        })
    }
}

/// Inventories one leaf under its exclusive fence and spools every record.
///
/// The aggregate logical-byte budget is charged while the fence is held so an
/// oversized store fails before any placement is read.
fn spool_fenced_inventory(
    node: &StoreNodeId,
    authority: &StoreGraphPhysicalAuthority,
    limits: StoreGraphVerificationLimits,
    spool_directory: &Path,
    logical_bytes: &mut u64,
) -> Result<(BlobInventorySummary, SpooledInventory), StoreGraphVerificationError> {
    let spool_error = |source| StoreGraphVerificationError::Spool {
        node: node.clone(),
        source,
    };
    let mut spool = InventorySpool::create(spool_directory).map_err(spool_error)?;

    let mut limit_failure = false;
    let mut spool_failure = None;
    let inventory = {
        let mut fence = authority
            .admin
            .acquire_inventory_fence()
            .map_err(|source| StoreGraphVerificationError::Inventory {
                node: node.clone(),
                source,
            })?;
        fence.visit_inventory(&mut |record| {
            *logical_bytes = logical_bytes
                .checked_add(record.logical_length())
                .filter(|total| *total <= limits.maximum_logical_bytes)
                .ok_or_else(|| {
                    limit_failure = true;
                    StoreError::Quota
                })?;
            spool.append(record).map_err(|source| {
                spool_failure = Some(source);
                StoreError::Quota
            })
        })
    };

    let summary = match (inventory, spool_failure) {
        (Ok(summary), _) => summary,
        (Err(_source), Some(source)) => return Err(spool_error(source)),
        (Err(_source), None) if limit_failure => {
            return Err(StoreGraphVerificationError::LimitExceeded {
                node: node.clone(),
                limit: StoreGraphVerificationLimit::LogicalBytes,
            });
        }
        (Err(source), None) => {
            return Err(StoreGraphVerificationError::Inventory {
                node: node.clone(),
                source,
            });
        }
    };
    let spooled = spool.finish().map_err(spool_error)?;
    Ok((summary, spooled))
}

/// Streams every spooled placement through its exact leaf to authenticated EOF.
///
/// This runs without the inventory fence because packed reads take the
/// shared lifecycle lock that the exclusive fence excludes.
fn authenticate_spooled_placements(
    node: &StoreNodeId,
    authority: &StoreGraphPhysicalAuthority,
    mut spooled: SpooledInventory,
) -> Result<(), StoreGraphVerificationError> {
    let spool_error = |source| StoreGraphVerificationError::Spool {
        node: node.clone(),
        source,
    };

    while let Some(record) = spooled.next_record().map_err(spool_error)? {
        let handle = authority
            .backend
            .read(record.id(), None)
            .map_err(|source| StoreGraphVerificationError::Read {
                node: node.clone(),
                id: record.id(),
                source,
            })?;
        if handle.logical_length() != record.logical_length() {
            return Err(StoreGraphVerificationError::LogicalLengthChanged {
                node: node.clone(),
                id: record.id(),
                inventoried: record.logical_length(),
                opened: handle.logical_length(),
            });
        }
        handle.copy_to(&mut io::sink()).map_err(|source| {
            StoreGraphVerificationError::Authenticate {
                node: node.clone(),
                id: record.id(),
                source,
            }
        })?;
    }
    Ok(())
}

/// Reacquires the fence and returns the leaf's closing inventory summary.
///
/// The closing pass stops as soon as it sees more records than the opening
/// inventory, so a growing leaf cannot extend the verification.
fn closing_inventory(
    node: &StoreNodeId,
    authority: &StoreGraphPhysicalAuthority,
    first: &BlobInventorySummary,
) -> Result<BlobInventorySummary, StoreGraphVerificationError> {
    let mut exceeded_opening_count = false;
    let inventory = {
        let mut fence = authority
            .admin
            .acquire_inventory_fence()
            .map_err(|source| StoreGraphVerificationError::Inventory {
                node: node.clone(),
                source,
            })?;
        let mut observed = 0_u64;
        fence.visit_inventory(&mut |_record| {
            observed = observed.checked_add(1).ok_or(StoreError::Quota)?;
            if observed > first.objects() {
                exceeded_opening_count = true;
                return Err(StoreError::Quota);
            }
            Ok(())
        })
    };

    match inventory {
        Ok(summary) => Ok(summary),
        Err(_source) if exceeded_opening_count => {
            Err(StoreGraphVerificationError::InventoryChanged {
                node: node.clone(),
                before: first.generation(),
                after: None,
            })
        }
        Err(source) => Err(StoreGraphVerificationError::Inventory {
            node: node.clone(),
            source,
        }),
    }
}

fn validate_backend_identity(
    node: &StoreNodeId,
    summary: &BlobInventorySummary,
) -> Result<(), StoreGraphVerificationError> {
    if summary.backend() == node.as_str() {
        return Ok(());
    }
    Err(StoreGraphVerificationError::BackendIdentityMismatch {
        node: node.clone(),
        expected: node.as_str().to_owned(),
        actual: summary.backend().to_owned(),
    })
}

/// Rejects a spool directory that is missing, a symlink, or not owner-only.
fn validate_spool_directory(path: &Path) -> Result<(), StoreGraphVerificationError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|source| {
        StoreGraphVerificationError::SpoolDirectory {
            path: path.to_owned(),
            source,
        }
    })?;
    if !metadata.file_type().is_dir() || metadata.mode() & 0o077 != 0 {
        return Err(StoreGraphVerificationError::InsecureSpoolDirectory {
            path: path.to_owned(),
        });
    }
    Ok(())
}

/// Width of one fixed spool record; see the module documentation.
const SPOOL_RECORD_BYTES: usize = 1 + 4 + 32 + 8;

/// Append-only spool of one leaf's fenced inventory records.
struct InventorySpool {
    writer: BufWriter<File>,
    records: u64,
}

impl InventorySpool {
    /// Creates an anonymous owner-only spool file in `directory`.
    ///
    /// On Linux the file is opened with `O_TMPFILE` and never has a name;
    /// otherwise it is unlinked immediately after creation. Either way it
    /// disappears when the handle is dropped, including on every error path.
    fn create(directory: &Path) -> io::Result<Self> {
        let file = tempfile::tempfile_in(directory)?;
        file.set_permissions(Permissions::from_mode(0o600))?;
        Ok(Self {
            writer: BufWriter::new(file),
            records: 0,
        })
    }

    fn append(&mut self, record: BlobInventoryRecord) -> io::Result<()> {
        self.writer.write_all(&encode_spool_record(record))?;
        self.records = self
            .records
            .checked_add(1)
            .ok_or_else(|| io::Error::other("inventory spool record count overflowed"))?;
        Ok(())
    }

    /// Flushes the spool and rewinds it for replay.
    fn finish(self) -> io::Result<SpooledInventory> {
        let mut file = self
            .writer
            .into_inner()
            .map_err(io::IntoInnerError::into_error)?;
        file.seek(SeekFrom::Start(0))?;
        Ok(SpooledInventory {
            reader: BufReader::new(file),
            remaining: self.records,
        })
    }
}

/// Sequential replay of a finished inventory spool.
struct SpooledInventory {
    reader: BufReader<File>,
    remaining: u64,
}

impl SpooledInventory {
    /// Returns the next spooled record, or `None` after the last one.
    fn next_record(&mut self) -> io::Result<Option<BlobInventoryRecord>> {
        if self.remaining == 0 {
            return Ok(None);
        }

        let mut bytes = [0_u8; SPOOL_RECORD_BYTES];
        self.reader.read_exact(&mut bytes)?;
        self.remaining -= 1;
        decode_spool_record(&bytes).map(Some)
    }
}

fn encode_spool_record(record: BlobInventoryRecord) -> [u8; SPOOL_RECORD_BYTES] {
    let id = record.id();
    let mut bytes = [0_u8; SPOOL_RECORD_BYTES];
    bytes[0] = spool_kind_tag(id.kind());
    bytes[1..5].copy_from_slice(&id.schema_version().to_be_bytes());
    bytes[5..37].copy_from_slice(&id.digest());
    bytes[37..].copy_from_slice(&record.logical_length().to_be_bytes());
    bytes
}

fn decode_spool_record(bytes: &[u8; SPOOL_RECORD_BYTES]) -> io::Result<BlobInventoryRecord> {
    let (tag, rest) = bytes.split_at(1);
    let (schema_version, rest) = rest.split_at(4);
    let (digest, logical_length) = rest.split_at(32);
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "corrupt inventory spool record");

    let id = ContentId {
        kind: spool_kind_from_tag(tag[0]).ok_or_else(invalid)?,
        schema_version: u32::from_be_bytes(schema_version.try_into().map_err(|_| invalid())?),
        digest: digest.try_into().map_err(|_| invalid())?,
    };
    let logical_length = u64::from_be_bytes(logical_length.try_into().map_err(|_| invalid())?);
    Ok(BlobInventoryRecord::new(id, logical_length))
}

/// Maps an object kind to its process-private spool tag.
const fn spool_kind_tag(kind: ObjectKind) -> u8 {
    match kind {
        ObjectKind::CampaignFact => 0,
        ObjectKind::CampaignSnapshot => 1,
        ObjectKind::MerkleNode => 2,
        ObjectKind::Scenario => 3,
        ObjectKind::Configuration => 4,
        ObjectKind::Policy => 5,
        ObjectKind::ExactManifest => 6,
        ObjectKind::RamExtent => 7,
        ObjectKind::DiskExtent => 8,
        ObjectKind::DeviceState => 9,
        ObjectKind::Observation => 10,
        ObjectKind::Finding => 11,
        ObjectKind::Projection => 12,
        ObjectKind::Trace => 13,
    }
}

/// Inverts [`spool_kind_tag`]; unknown tags indicate a corrupt spool.
const fn spool_kind_from_tag(tag: u8) -> Option<ObjectKind> {
    Some(match tag {
        0 => ObjectKind::CampaignFact,
        1 => ObjectKind::CampaignSnapshot,
        2 => ObjectKind::MerkleNode,
        3 => ObjectKind::Scenario,
        4 => ObjectKind::Configuration,
        5 => ObjectKind::Policy,
        6 => ObjectKind::ExactManifest,
        7 => ObjectKind::RamExtent,
        8 => ObjectKind::DiskExtent,
        9 => ObjectKind::DeviceState,
        10 => ObjectKind::Observation,
        11 => ObjectKind::Finding,
        12 => ObjectKind::Projection,
        13 => ObjectKind::Trace,
        _ => return None,
    })
}

#[cfg(test)]
mod spool_tests {
    use super::*;

    #[test]
    fn spool_records_round_trip_every_object_kind() {
        for tag in 0..=u8::MAX {
            let Some(kind) = spool_kind_from_tag(tag) else {
                continue;
            };
            assert_eq!(spool_kind_tag(kind), tag);

            let record = BlobInventoryRecord::new(
                ContentId::for_bytes(kind, 7, &[tag]),
                u64::MAX - u64::from(tag),
            );
            let decoded = decode_spool_record(&encode_spool_record(record));
            assert!(matches!(decoded, Ok(value) if value == record));
        }
    }
}
