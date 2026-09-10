//! Broker-owned source realization admission and descriptor custody.
//!
//! The controller-facing Mount protocol carries only a
//! [`SourceRealizationBindingV1`]. A fixed authenticated provider must resolve
//! that binding and attest the exact descriptor before this registry can admit
//! a pin. Merely creating a predictable directory never creates authority.
//! The production daemon currently composes [`UnavailableSourcePins`], so
//! native source preparation fails closed until a concrete provider channel is
//! implemented and configured. The durable registry prototype is compiled only
//! for unit tests because its JSON snapshot is not transactionally coupled to
//! the mount-resource journal; production cannot compose the two stores as one
//! atomic authority update.

#[cfg(test)]
use aos_sandbox_core::ObjectDigest;
#[cfg(test)]
use aos_sandbox_linux::inventory::MountId;
use aos_sandbox_linux::path::ResolvedPath;
#[cfg(test)]
use aos_sandbox_linux::path::{BeneathRoot, FileIdentity, FileType};
use aos_sandbox_protocol::SourceRealizationBindingV1;
#[cfg(test)]
use serde::{Deserialize, Serialize};
#[cfg(test)]
use std::collections::BTreeMap;
#[cfg(test)]
use std::io::Write as _;
#[cfg(test)]
use std::os::fd::OwnedFd;
#[cfg(test)]
use std::path::Path;

#[cfg(test)]
use crate::keeper::{SourceDescriptorStore, SourcePinName};
use crate::{MountError, Result};

/// Maximum distinct source pins retained by one broker instance.
pub const MAXIMUM_SOURCE_PINS: usize = 1_024;
#[cfg(test)]
const SOURCE_PIN_FILE: &str = "source-pins.json";
#[cfg(test)]
const SOURCE_PIN_NEXT_FILE: &str = "source-pins.next";
#[cfg(test)]
const SOURCE_PIN_FORMAT_VERSION: u16 = 1;
#[cfg(test)]
const MAXIMUM_SOURCE_PIN_BYTES: usize = 4 * 1024 * 1024;

/// Classifies the provider proof that permits one native realization.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg(test)]
pub(crate) enum SourcePinProofClass {
    /// The provider realized the exact immutable portable tree.
    ImmutableTree,
    /// The provider pinned one same-node live export generation.
    LocalLive,
    /// The provider pinned one externally versioned replica generation.
    BestEffortReplica,
}

/// Names a durable resource phase that retains source custody.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(test)]
pub(crate) enum SourcePinReferenceKind {
    /// Catalog preparation may still need the provider descriptor.
    Preparing,
    /// A detached mount derived from this source remains retained.
    Detached,
    /// An installed mount derived from this source remains observable.
    Installed,
    /// A replaced generation is draining and may require recovery inspection.
    Draining,
}

/// Supplies counts recomputed from authenticated durable mount resource phases.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg(test)]
pub(crate) struct SourcePinReferenceCountsV1 {
    /// Resources whose catalog preparation is in flight.
    pub(crate) preparing: u32,
    /// Detached resources still retained by the broker.
    pub(crate) detached: u32,
    /// Installed resources still present in a payload namespace.
    pub(crate) installed: u32,
    /// Replaced resources whose drain lifecycle is incomplete.
    pub(crate) draining: u32,
}

#[cfg(test)]
impl SourcePinReferenceCountsV1 {
    pub(crate) fn increment(&mut self, kind: SourcePinReferenceKind) -> Result<()> {
        let value = match kind {
            SourcePinReferenceKind::Preparing => &mut self.preparing,
            SourcePinReferenceKind::Detached => &mut self.detached,
            SourcePinReferenceKind::Installed => &mut self.installed,
            SourcePinReferenceKind::Draining => &mut self.draining,
        };
        *value = value.checked_add(1).ok_or_else(|| {
            MountError::State("recovered source-pin reference count overflowed".to_owned())
        })?;
        Ok(())
    }
}

/// Carries reference counts derived from a validated durable resource table.
///
/// This value has no public constructor. Mount recovery creates it only after
/// authenticating and validating the complete journal-backed resource table,
/// preventing an integration from labeling arbitrary counters as authority.
///
/// ```compile_fail
/// use aos_sandbox_mount::source_pin::RecoveredSourcePinReferencesV1;
///
/// let fabricated = RecoveredSourcePinReferencesV1::default();
/// ```
#[derive(Debug)]
#[cfg(test)]
pub struct RecoveredSourcePinReferencesV1 {
    counts: BTreeMap<ObjectDigest, SourcePinReferenceCountsV1>,
}

#[cfg(test)]
impl RecoveredSourcePinReferencesV1 {
    pub(crate) fn from_counts(counts: BTreeMap<ObjectDigest, SourcePinReferenceCountsV1>) -> Self {
        Self { counts }
    }

    pub(crate) fn into_counts(self) -> BTreeMap<ObjectDigest, SourcePinReferenceCountsV1> {
        self.counts
    }

    #[cfg(test)]
    fn for_test(counts: BTreeMap<ObjectDigest, SourcePinReferenceCountsV1>) -> Self {
        Self { counts }
    }
}

#[cfg(test)]
impl From<SourcePinReferenceCountsV1> for SourcePinReferences {
    fn from(value: SourcePinReferenceCountsV1) -> Self {
        Self {
            preparing: value.preparing,
            detached: value.detached,
            installed: value.installed,
            draining: value.draining,
        }
    }
}

/// Fixes the sole provider generation and Linux boot trusted by one registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(test)]
pub(crate) struct SourcePinTrustV1 {
    /// Authenticated provider service identity.
    pub(crate) provider_id: [u8; 16],
    /// Exact nonzero provider generation.
    pub(crate) provider_generation: u64,
    /// Exact current Linux boot identity.
    pub(crate) kernel_boot_id: [u8; 16],
}

/// Attests a provider-selected descriptor for one exact logical binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(test)]
pub(crate) struct SourcePinAttestationV1 {
    /// Domain-separated digest of the complete logical source binding.
    binding_digest: ObjectDigest,
    /// Fixed provider service identity selected by broker configuration.
    provider_id: [u8; 16],
    /// Nonzero provider generation fencing provider restart or replacement.
    provider_generation: u64,
    /// Linux boot in which this physical descriptor was realized.
    kernel_boot_id: [u8; 16],
    /// Exact descriptor device number.
    device: u64,
    /// Exact descriptor inode number.
    inode: u64,
    /// Kernel-lifetime unique mount containing the descriptor.
    mount_id: MountId,
    /// Closed proof semantics supplied by the provider.
    proof_class: SourcePinProofClass,
}

/// Owns one duplicated, broker-verified descriptor and its physical proof.
#[derive(Debug)]
pub struct ResolvedSourcePin {
    source: ResolvedPath,
}

impl ResolvedSourcePin {
    /// Returns the pinned source descriptor used by the mount worker.
    #[must_use]
    pub const fn source(&self) -> &ResolvedPath {
        &self.source
    }

    /// Consumes the proof wrapper and returns its pinned source descriptor.
    #[must_use]
    pub fn into_source(self) -> ResolvedPath {
        self.source
    }
}

/// Resolves logical source authority through broker-owned pin state.
pub trait SourcePinStore {
    /// Reports whether this store currently has an executable provider backend.
    #[must_use]
    fn is_available(&self) -> bool;

    /// Duplicates the exact admitted source descriptor for an operation.
    ///
    /// # Errors
    ///
    /// Returns an error when no fixed provider admitted the binding, custody
    /// was lost, boot or provider evidence changed, or the registry is poisoned.
    fn resolve(&self, binding: &SourceRealizationBindingV1) -> Result<ResolvedSourcePin>;
}

/// Rejects every source because no concrete fixed provider is configured.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailableSourcePins;

impl SourcePinStore for UnavailableSourcePins {
    fn is_available(&self) -> bool {
        false
    }

    fn resolve(&self, _binding: &SourceRealizationBindingV1) -> Result<ResolvedSourcePin> {
        Err(MountError::Worker(
            "no fixed authenticated filesystem-view source provider is configured".to_owned(),
        ))
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg(test)]
struct SourcePinReferences {
    preparing: u32,
    detached: u32,
    installed: u32,
    draining: u32,
}

#[cfg(test)]
impl SourcePinReferences {
    const fn is_empty(self) -> bool {
        self.preparing == 0 && self.detached == 0 && self.installed == 0 && self.draining == 0
    }

    fn increment(&mut self, kind: SourcePinReferenceKind) -> Result<()> {
        let value = match kind {
            SourcePinReferenceKind::Preparing => &mut self.preparing,
            SourcePinReferenceKind::Detached => &mut self.detached,
            SourcePinReferenceKind::Installed => &mut self.installed,
            SourcePinReferenceKind::Draining => &mut self.draining,
        };
        *value = value
            .checked_add(1)
            .ok_or_else(|| MountError::State("source-pin reference count overflowed".to_owned()))?;
        Ok(())
    }

    fn decrement(&mut self, kind: SourcePinReferenceKind) -> Result<()> {
        let value = match kind {
            SourcePinReferenceKind::Preparing => &mut self.preparing,
            SourcePinReferenceKind::Detached => &mut self.detached,
            SourcePinReferenceKind::Installed => &mut self.installed,
            SourcePinReferenceKind::Draining => &mut self.draining,
        };
        *value = value.checked_sub(1).ok_or_else(|| {
            MountError::State("source-pin reference count underflowed".to_owned())
        })?;
        Ok(())
    }
}

#[derive(Debug)]
#[cfg(test)]
struct SourcePinEntry {
    source: ResolvedPath,
    attestation: SourcePinAttestationV1,
    references: SourcePinReferences,
}

/// Retains source descriptors admitted by one fixed authenticated provider.
///
/// This registry is intentionally not constructed by the production daemon
/// yet. It is the provider-facing authority boundary and supports exact
/// descriptor adoption without exposing a controller SCM_RIGHTS ingress.
#[cfg(test)]
#[derive(Debug)]
struct BrokerOwnedSourcePins {
    provider_id: [u8; 16],
    provider_generation: u64,
    kernel_boot_id: [u8; 16],
    entries: BTreeMap<ObjectDigest, SourcePinEntry>,
    poisoned: bool,
}

#[cfg(test)]
impl BrokerOwnedSourcePins {
    /// Constructs an empty registry for one fixed provider generation and boot.
    ///
    /// # Errors
    ///
    /// Returns an error when a trusted identity or generation uses its zero
    /// sentinel.
    fn new(trust: SourcePinTrustV1) -> Result<Self> {
        if trust.provider_id == [0; 16]
            || trust.provider_generation == 0
            || trust.kernel_boot_id == [0; 16]
        {
            return Err(MountError::State(
                "source-pin provider generation and boot identities must be nonzero".to_owned(),
            ));
        }
        Ok(Self {
            provider_id: trust.provider_id,
            provider_generation: trust.provider_generation,
            kernel_boot_id: trust.kernel_boot_id,
            entries: BTreeMap::new(),
            poisoned: false,
        })
    }

    /// Admits one exact provider descriptor after verifying all attested facts.
    ///
    /// Re-admitting an identical binding and physical proof is idempotent.
    /// The same binding with a different proof poisons the registry so neither
    /// version can authorize mutation in this process.
    ///
    /// # Errors
    ///
    /// Returns an error for an untrusted provider or boot, mismatched binding,
    /// consistency/proof substitution, non-directory descriptor, identity or
    /// mount-ID mismatch, capacity exhaustion, or equivocation.
    fn admit(
        &mut self,
        binding: &SourceRealizationBindingV1,
        attestation: SourcePinAttestationV1,
        source: ResolvedPath,
    ) -> Result<()> {
        self.ensure_healthy()?;
        validate_attestation(
            binding,
            attestation,
            source.identity(),
            MountId::from_fd(source.as_fd()).map_err(linux_error)?,
            self.provider_id,
            self.provider_generation,
            self.kernel_boot_id,
        )?;

        if let Some(existing) = self.entries.get(&binding.digest()) {
            if existing.attestation == attestation
                && existing.source.identity() == source.identity()
            {
                return Ok(());
            }
            self.poisoned = true;
            return Err(MountError::State(
                "source provider equivocated for one logical binding".to_owned(),
            ));
        }
        if self.entries.len() >= MAXIMUM_SOURCE_PINS {
            return Err(MountError::Worker("source-pin registry is full".to_owned()));
        }
        self.entries.insert(
            binding.digest(),
            SourcePinEntry {
                source,
                attestation,
                references: SourcePinReferences::default(),
            },
        );
        Ok(())
    }

    /// Removes an unreferenced pin from broker custody.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry is poisoned, the pin is unknown, or
    /// preparing, detached, installed, or draining resources still reference it.
    fn reap(&mut self, binding: &SourceRealizationBindingV1) -> Result<()> {
        self.ensure_healthy()?;
        let digest = binding.digest();
        let entry = self
            .entries
            .get(&digest)
            .ok_or_else(|| MountError::Worker("source pin is not registered".to_owned()))?;
        if !entry.references.is_empty() {
            return Err(MountError::Worker(
                "source pin remains referenced by a mount resource".to_owned(),
            ));
        }
        self.entries.remove(&digest);
        Ok(())
    }

    fn ensure_healthy(&self) -> Result<()> {
        if self.poisoned {
            Err(MountError::State(
                "source-pin registry is poisoned by provider equivocation".to_owned(),
            ))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
impl SourcePinStore for BrokerOwnedSourcePins {
    fn is_available(&self) -> bool {
        !self.poisoned
    }

    fn resolve(&self, binding: &SourceRealizationBindingV1) -> Result<ResolvedSourcePin> {
        self.ensure_healthy()?;
        let entry = self.entries.get(&binding.digest()).ok_or_else(|| {
            MountError::Worker("exact source binding has no admitted broker pin".to_owned())
        })?;
        let duplicate = rustix::io::fcntl_dupfd_cloexec(entry.source.as_fd(), 0)
            .map_err(|error| MountError::Worker(error.to_string()))?;
        let source = ResolvedPath::from_inherited(duplicate).map_err(linux_error)?;
        let mount_id = MountId::from_fd(source.as_fd()).map_err(linux_error)?;
        validate_attestation(
            binding,
            entry.attestation,
            source.identity(),
            mount_id,
            self.provider_id,
            self.provider_generation,
            self.kernel_boot_id,
        )?;
        Ok(ResolvedSourcePin { source })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg(test)]
enum DurableSourcePinState {
    Active,
    Tombstone,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg(test)]
struct DurableSourcePinRow {
    canonical_binding: Vec<u8>,
    binding_digest: [u8; 32],
    provider_id: [u8; 16],
    provider_generation: u64,
    kernel_boot_id: [u8; 16],
    device: u64,
    inode: u64,
    mount_id: u64,
    proof_class: SourcePinProofClass,
    references: SourcePinReferences,
    state: DurableSourcePinState,
}

#[cfg(test)]
impl DurableSourcePinRow {
    fn from_attestation(
        binding: &SourceRealizationBindingV1,
        attestation: SourcePinAttestationV1,
    ) -> Self {
        Self {
            canonical_binding: binding.canonical_bytes(),
            binding_digest: *attestation.binding_digest.as_bytes(),
            provider_id: attestation.provider_id,
            provider_generation: attestation.provider_generation,
            kernel_boot_id: attestation.kernel_boot_id,
            device: attestation.device,
            inode: attestation.inode,
            mount_id: attestation.mount_id.get(),
            proof_class: attestation.proof_class,
            references: SourcePinReferences::default(),
            state: DurableSourcePinState::Active,
        }
    }

    fn attestation(&self) -> Result<SourcePinAttestationV1> {
        Ok(SourcePinAttestationV1 {
            binding_digest: ObjectDigest::from_bytes(self.binding_digest),
            provider_id: self.provider_id,
            provider_generation: self.provider_generation,
            kernel_boot_id: self.kernel_boot_id,
            device: self.device,
            inode: self.inode,
            mount_id: MountId::new(self.mount_id).map_err(linux_error)?,
            proof_class: self.proof_class,
        })
    }

    fn matches_attestation(
        &self,
        binding: &SourceRealizationBindingV1,
        attestation: SourcePinAttestationV1,
    ) -> bool {
        self.state == DurableSourcePinState::Active
            && self.canonical_binding == binding.canonical_bytes()
            && self.binding_digest == *attestation.binding_digest.as_bytes()
            && self.provider_id == attestation.provider_id
            && self.provider_generation == attestation.provider_generation
            && self.kernel_boot_id == attestation.kernel_boot_id
            && self.device == attestation.device
            && self.inode == attestation.inode
            && self.mount_id == attestation.mount_id.get()
            && self.proof_class == attestation.proof_class
    }

    fn validate(&self) -> Result<()> {
        if self.binding_digest == [0; 32]
            || self.provider_id == [0; 16]
            || self.provider_generation == 0
            || self.kernel_boot_id == [0; 16]
            || self.device == 0
            || self.inode == 0
            || self.mount_id == 0
        {
            return Err(MountError::State(
                "durable source-pin row contains a sentinel".to_owned(),
            ));
        }
        let binding = SourceRealizationBindingV1::from_canonical_bytes(&self.canonical_binding)
            .map_err(|error| MountError::State(error.to_string()))?;
        if binding.digest().as_bytes() != &self.binding_digest {
            return Err(MountError::State(
                "durable source-pin binding bytes and digest disagree".to_owned(),
            ));
        }
        if self.proof_class != proof_class_for_binding(&binding)? {
            return Err(MountError::State(
                "durable source-pin proof class contradicts its binding".to_owned(),
            ));
        }
        if self.state == DurableSourcePinState::Tombstone && !self.references.is_empty() {
            return Err(MountError::State(
                "source-pin tombstone retains live references".to_owned(),
            ));
        }
        let _ = self.attestation()?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg(test)]
struct DurableSourcePinSnapshot {
    version: u16,
    generation: u64,
    rows: Vec<DurableSourcePinRow>,
}

#[cfg(test)]
impl DurableSourcePinSnapshot {
    fn validate(&self) -> Result<()> {
        if self.version != SOURCE_PIN_FORMAT_VERSION
            || self.rows.len() > MAXIMUM_SOURCE_PINS
            || (self.generation == 0 && !self.rows.is_empty())
        {
            return Err(MountError::State(
                "source-pin snapshot version, generation, or bound is invalid".to_owned(),
            ));
        }
        let mut previous = None;
        for row in &self.rows {
            row.validate()?;
            if previous.is_some_and(|digest| digest >= row.binding_digest) {
                return Err(MountError::State(
                    "source-pin rows are not strictly binding-digest ordered".to_owned(),
                ));
            }
            previous = Some(row.binding_digest);
        }
        Ok(())
    }

    fn advance(&mut self) -> Result<()> {
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or_else(|| MountError::State("source-pin generation overflowed".to_owned()))?;
        Ok(())
    }
}

#[derive(Debug)]
#[cfg(test)]
struct DurableSourcePinEntry {
    row: DurableSourcePinRow,
    source: Option<ResolvedPath>,
}

/// Persists source-pin proofs and coordinates PID 1 descriptor custody.
///
/// Active rows authorize resolution only while an exactly named adopted
/// descriptor reproduces device, inode, unique mount ID, provider, and boot.
/// Missing custody for a current row fails startup. Provider- or boot-stale
/// rows remain audit-visible but unusable after their custody is removed.
/// Orphan custody without a durable row is deterministically removed;
/// substituted names and physical mismatches fail startup.
#[derive(Debug)]
#[cfg(test)]
pub(crate) struct DurableSourcePins<K> {
    root: BeneathRoot,
    provider_id: [u8; 16],
    provider_generation: u64,
    kernel_boot_id: [u8; 16],
    keeper: K,
    generation: u64,
    entries: BTreeMap<ObjectDigest, DurableSourcePinEntry>,
    poisoned: bool,
    #[cfg(test)]
    publication_fault: Option<TestPublicationFault>,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TestPublicationFault {
    BeforeRename,
    AfterRename,
}

#[cfg(test)]
impl<K: SourceDescriptorStore> DurableSourcePins<K> {
    /// Opens durable pin rows and adopts an exact same-boot descriptor table.
    ///
    /// # Errors
    ///
    /// Returns an error unless `path` resolves directly to a mode-0700
    /// directory owned by the effective service identity, snapshot rows are
    /// canonical, every current adopted physical identity reproduces its
    /// durable attestation, or orphan custody cannot be removed and negatively
    /// read back.
    pub(crate) fn open(
        path: impl AsRef<Path>,
        trust: SourcePinTrustV1,
        keeper: K,
        mut adopted: BTreeMap<SourcePinName, ResolvedPath>,
        recovered_references: RecoveredSourcePinReferencesV1,
    ) -> Result<Self> {
        if trust.provider_id == [0; 16]
            || trust.provider_generation == 0
            || trust.kernel_boot_id == [0; 16]
        {
            return Err(MountError::State(
                "source-pin provider and boot identities must be nonzero".to_owned(),
            ));
        }
        let path = path.as_ref();
        let descriptor: OwnedFd = rustix::fs::open(
            path,
            rustix::fs::OFlags::PATH
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| MountError::State(error.to_string()))?;
        let metadata =
            rustix::fs::fstat(&descriptor).map_err(|error| MountError::State(error.to_string()))?;
        if metadata.st_uid != rustix::process::geteuid().as_raw()
            || metadata.st_mode & 0o7777 != 0o700
        {
            return Err(MountError::State(
                "source-pin state root must be owned by the service with mode 0700".to_owned(),
            ));
        }
        let root = BeneathRoot::from_owned(descriptor).map_err(linux_error)?;
        let snapshot = read_snapshot(&root)?;

        let mut references = recovered_references.into_counts();
        let mut entries = BTreeMap::new();
        let mut physical_identities = std::collections::BTreeSet::new();
        let mut completed_tombstone = false;
        for row in snapshot.rows {
            let digest = ObjectDigest::from_bytes(row.binding_digest);
            let expected_references = references.remove(&digest).unwrap_or_default();
            if row.references != expected_references.into() {
                return Err(MountError::State(
                    "persisted source-pin counts differ from authenticated resource phases"
                        .to_owned(),
                ));
            }
            let name = SourcePinName::from_digest(row.binding_digest);
            if row.state == DurableSourcePinState::Tombstone {
                adopted.remove(&name);
                keeper.remove_source(&name)?;
                if keeper.contains_source(&name)? {
                    return Err(MountError::State(
                        "tombstoned source descriptor survived keeper removal".to_owned(),
                    ));
                }
                completed_tombstone = true;
                continue;
            }
            let source = if row.provider_id == trust.provider_id
                && row.provider_generation == trust.provider_generation
                && row.kernel_boot_id == trust.kernel_boot_id
            {
                Some(adopted.remove(&name).ok_or_else(|| {
                    MountError::State(
                        "active source-pin row is missing descriptor-store custody".to_owned(),
                    )
                })?)
            } else {
                adopted.remove(&name);
                keeper.remove_source(&name)?;
                if keeper.contains_source(&name)? {
                    return Err(MountError::State(
                        "stale source custody survived deterministic removal".to_owned(),
                    ));
                }
                None
            };
            if let Some(source) = source.as_ref() {
                verify_adopted_source(&row, source)?;
                if !physical_identities.insert((row.device, row.inode, row.mount_id)) {
                    return Err(MountError::State(
                        "two source-pin rows alias one adopted physical descriptor".to_owned(),
                    ));
                }
                if !keeper.contains_source(&name)? {
                    return Err(MountError::State(
                        "adopted source descriptor is absent from keeper inventory".to_owned(),
                    ));
                }
            }
            entries.insert(digest, DurableSourcePinEntry { row, source });
        }
        for (name, source) in adopted {
            keeper.remove_source(&name)?;
            if keeper.contains_source(&name)? {
                return Err(MountError::State(
                    "orphan source custody survived deterministic removal".to_owned(),
                ));
            }
            drop(source);
        }

        let mut registry = Self {
            root,
            provider_id: trust.provider_id,
            provider_generation: trust.provider_generation,
            kernel_boot_id: trust.kernel_boot_id,
            keeper,
            generation: snapshot.generation,
            entries,
            poisoned: false,
            #[cfg(test)]
            publication_fault: None,
        };
        if !references.is_empty() {
            return Err(MountError::State(
                "authenticated resource phases reference an unknown source pin".to_owned(),
            ));
        }
        if completed_tombstone {
            registry.publish()?;
        }
        Ok(registry)
    }

    /// Stores and durably publishes one fixed-provider source pin.
    ///
    /// PID 1 storage and positive readback complete before the active row is
    /// published. A same-binding physical conflict poisons the registry.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid attestation, equivocation, capacity,
    /// keeper/barrier/readback failure, or durable publication failure.
    pub(crate) fn admit(
        &mut self,
        binding: &SourceRealizationBindingV1,
        attestation: SourcePinAttestationV1,
        source: ResolvedPath,
    ) -> Result<()> {
        self.ensure_healthy()?;
        validate_attestation(
            binding,
            attestation,
            source.identity(),
            MountId::from_fd(source.as_fd()).map_err(linux_error)?,
            self.provider_id,
            self.provider_generation,
            self.kernel_boot_id,
        )?;
        if attestation.provider_generation != self.provider_generation {
            return Err(MountError::Worker(
                "source provider generation differs from configured trust".to_owned(),
            ));
        }
        let digest = binding.digest();
        if let Some(existing) = self.entries.get(&digest) {
            if existing.row.matches_attestation(binding, attestation)
                && existing
                    .source
                    .as_ref()
                    .is_some_and(|retained| retained.identity() == source.identity())
            {
                return Ok(());
            }
            self.poisoned = true;
            return Err(MountError::State(
                "source provider equivocated for one durable binding".to_owned(),
            ));
        }
        if self.entries.len() >= MAXIMUM_SOURCE_PINS {
            return Err(MountError::Worker("source-pin registry is full".to_owned()));
        }

        let name = SourcePinName::from_digest(*digest.as_bytes());
        if self.keeper.contains_source(&name)? {
            return Err(MountError::State(
                "source descriptor-store name exists without a durable row".to_owned(),
            ));
        }
        self.keeper.store_source(&name, source.as_fd())?;
        if !self.keeper.contains_source(&name)? {
            return Err(MountError::State(
                "source descriptor-store positive readback failed".to_owned(),
            ));
        }

        self.entries.insert(
            digest,
            DurableSourcePinEntry {
                row: DurableSourcePinRow::from_attestation(binding, attestation),
                source: Some(source),
            },
        );
        self.publish()
    }

    /// Increments one durable lifecycle reference.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown/unusable pin, overflow, poison, or a
    /// durable publication failure.
    pub(crate) fn retain(
        &mut self,
        binding: &SourceRealizationBindingV1,
        kind: SourcePinReferenceKind,
    ) -> Result<()> {
        self.mutate_references(binding, true, |references| references.increment(kind))
    }

    /// Decrements one durable lifecycle reference.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown pin, underflow, poison, or publication
    /// failure. Any ambiguous publication poisons all in-process authority.
    pub(crate) fn release(
        &mut self,
        binding: &SourceRealizationBindingV1,
        kind: SourcePinReferenceKind,
    ) -> Result<()> {
        self.mutate_references(binding, false, |references| references.decrement(kind))
    }

    /// Tombstones and removes one fully unreferenced descriptor.
    ///
    /// The tombstone is durable before PID 1 removal. Failed removal or
    /// negative readback leaves the tombstone unusable for deterministic retry.
    ///
    /// # Errors
    ///
    /// Returns an error while any lifecycle reference remains or when either
    /// durable publication, keeper removal, or negative readback fails.
    pub(crate) fn reap(&mut self, binding: &SourceRealizationBindingV1) -> Result<()> {
        self.ensure_healthy()?;
        let digest = binding.digest();
        let entry = self
            .entries
            .get_mut(&digest)
            .ok_or_else(|| MountError::Worker("source pin is not registered".to_owned()))?;
        if !entry.row.references.is_empty() {
            return Err(MountError::Worker(
                "source pin remains referenced by a mount resource".to_owned(),
            ));
        }
        entry.row.state = DurableSourcePinState::Tombstone;
        let tombstone = entry.row.clone();
        self.publish()?;

        let name = SourcePinName::from_digest(*digest.as_bytes());
        self.keeper.remove_source(&name)?;
        if self.keeper.contains_source(&name)? {
            return Err(MountError::State(
                "source descriptor-store negative readback failed".to_owned(),
            ));
        }
        if let Some(entry) = self.entries.get_mut(&digest) {
            entry.source = None;
        }
        self.entries.remove(&digest);
        if let Err(error) = self.publish() {
            self.entries.insert(
                digest,
                DurableSourcePinEntry {
                    row: tombstone,
                    source: None,
                },
            );
            return Err(error);
        }
        Ok(())
    }

    fn mutate_references(
        &mut self,
        binding: &SourceRealizationBindingV1,
        require_current_custody: bool,
        mutation: impl FnOnce(&mut SourcePinReferences) -> Result<()>,
    ) -> Result<()> {
        self.ensure_healthy()?;
        let digest = binding.digest();
        let entry = self
            .entries
            .get_mut(&digest)
            .ok_or_else(|| MountError::Worker("source pin is not registered".to_owned()))?;
        let durable_binding =
            SourceRealizationBindingV1::from_canonical_bytes(&entry.row.canonical_binding)
                .map_err(|error| MountError::State(error.to_string()))?;
        if durable_binding != *binding {
            return Err(MountError::State(
                "reference mutation binding differs from durable authority".to_owned(),
            ));
        }
        if entry.row.state != DurableSourcePinState::Active
            || (require_current_custody && entry.source.is_none())
        {
            return Err(MountError::Worker("source pin is not usable".to_owned()));
        }
        mutation(&mut entry.row.references)?;
        self.publish()
    }

    fn ensure_healthy(&self) -> Result<()> {
        if self.poisoned {
            Err(MountError::State(
                "durable source-pin registry is poisoned".to_owned(),
            ))
        } else {
            Ok(())
        }
    }

    fn publish(&mut self) -> Result<()> {
        let mut snapshot = DurableSourcePinSnapshot {
            version: SOURCE_PIN_FORMAT_VERSION,
            generation: self.generation,
            rows: self
                .entries
                .values()
                .map(|entry| entry.row.clone())
                .collect(),
        };
        let result = (|| {
            snapshot.advance()?;
            snapshot.validate()?;
            publish_snapshot(
                &self.root,
                &snapshot,
                #[cfg(test)]
                self.publication_fault.take(),
            )
        })();
        match result {
            Ok(()) => {
                self.generation = snapshot.generation;
                Ok(())
            }
            Err(error) => {
                // A failed rename or directory fsync has an unknowable durable
                // result. No in-process entry may authorize further effects.
                self.poisoned = true;
                Err(error)
            }
        }
    }
}

#[cfg(test)]
impl<K: SourceDescriptorStore> SourcePinStore for DurableSourcePins<K> {
    fn is_available(&self) -> bool {
        !self.poisoned
    }

    fn resolve(&self, binding: &SourceRealizationBindingV1) -> Result<ResolvedSourcePin> {
        self.ensure_healthy()?;
        let entry = self.entries.get(&binding.digest()).ok_or_else(|| {
            MountError::Worker("exact source binding has no durable broker pin".to_owned())
        })?;
        if entry.row.state != DurableSourcePinState::Active
            || entry.row.provider_id != self.provider_id
            || entry.row.provider_generation != self.provider_generation
            || entry.row.kernel_boot_id != self.kernel_boot_id
        {
            return Err(MountError::Worker(
                "source pin is tombstoned, stale-boot, or provider-stale".to_owned(),
            ));
        }
        let retained = entry.source.as_ref().ok_or_else(|| {
            MountError::Worker("source-pin row has no adopted descriptor custody".to_owned())
        })?;
        let durable_binding =
            SourceRealizationBindingV1::from_canonical_bytes(&entry.row.canonical_binding)
                .map_err(|error| MountError::State(error.to_string()))?;
        if &durable_binding != binding {
            return Err(MountError::State(
                "resolved source binding differs from durable canonical authority".to_owned(),
            ));
        }
        let duplicate = rustix::io::fcntl_dupfd_cloexec(retained.as_fd(), 0)
            .map_err(|error| MountError::Worker(error.to_string()))?;
        let source = ResolvedPath::from_inherited(duplicate).map_err(linux_error)?;
        let attestation = entry.row.attestation()?;
        validate_attestation(
            binding,
            attestation,
            source.identity(),
            MountId::from_fd(source.as_fd()).map_err(linux_error)?,
            self.provider_id,
            self.provider_generation,
            self.kernel_boot_id,
        )?;
        Ok(ResolvedSourcePin { source })
    }
}

#[cfg(test)]
fn verify_adopted_source(row: &DurableSourcePinRow, source: &ResolvedPath) -> Result<()> {
    if source.identity().file_type != FileType::Directory
        || source.identity().device != row.device
        || source.identity().inode != row.inode
        || MountId::from_fd(source.as_fd()).map_err(linux_error)?.get() != row.mount_id
    {
        return Err(MountError::State(
            "adopted source descriptor differs from its durable physical proof".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
fn read_snapshot(root: &BeneathRoot) -> Result<DurableSourcePinSnapshot> {
    let file = match root.open_regular(Path::new(SOURCE_PIN_FILE)) {
        Ok(file) => file,
        Err(aos_sandbox_linux::Error::Syscall { source, .. })
            if source.raw_os_error() == Some(rustix::io::Errno::NOENT.raw_os_error()) =>
        {
            return Ok(DurableSourcePinSnapshot {
                version: SOURCE_PIN_FORMAT_VERSION,
                generation: 0,
                rows: Vec::new(),
            });
        }
        Err(error) => return Err(linux_error(error)),
    };
    let metadata =
        rustix::fs::fstat(file.as_fd()).map_err(|error| MountError::State(error.to_string()))?;
    if metadata.st_uid != rustix::process::geteuid().as_raw() || metadata.st_mode & 0o7777 != 0o600
    {
        return Err(MountError::State(
            "source-pin snapshot must be owned by the service with mode 0600".to_owned(),
        ));
    }
    let bytes = file
        .read_bounded(MAXIMUM_SOURCE_PIN_BYTES)
        .map_err(linux_error)?;
    let snapshot: DurableSourcePinSnapshot =
        serde_json::from_slice(&bytes).map_err(|error| MountError::State(error.to_string()))?;
    snapshot.validate()?;
    let canonical =
        serde_json::to_vec(&snapshot).map_err(|error| MountError::State(error.to_string()))?;
    if canonical != bytes {
        return Err(MountError::State(
            "source-pin snapshot JSON is not canonical".to_owned(),
        ));
    }
    Ok(snapshot)
}

#[cfg(test)]
fn publish_snapshot(
    root: &BeneathRoot,
    snapshot: &DurableSourcePinSnapshot,
    #[cfg(test)] publication_fault: Option<TestPublicationFault>,
) -> Result<()> {
    let bytes =
        serde_json::to_vec(snapshot).map_err(|error| MountError::State(error.to_string()))?;
    if bytes.len() > MAXIMUM_SOURCE_PIN_BYTES {
        return Err(MountError::State(
            "source-pin snapshot exceeds four MiB".to_owned(),
        ));
    }
    match rustix::fs::unlinkat(
        root.as_fd(),
        SOURCE_PIN_NEXT_FILE,
        rustix::fs::AtFlags::empty(),
    ) {
        Ok(()) | Err(rustix::io::Errno::NOENT) => {}
        Err(error) => return Err(MountError::State(error.to_string())),
    }
    let descriptor = rustix::fs::openat(
        root.as_fd(),
        SOURCE_PIN_NEXT_FILE,
        rustix::fs::OFlags::WRONLY
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::EXCL
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .map_err(|error| MountError::State(error.to_string()))?;
    let mut file = std::fs::File::from(descriptor);
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| MountError::State(error.to_string()))?;
    drop(file);
    #[cfg(test)]
    if publication_fault == Some(TestPublicationFault::BeforeRename) {
        return Err(MountError::State(
            "injected source-pin failure before rename".to_owned(),
        ));
    }
    rustix::fs::renameat(
        root.as_fd(),
        SOURCE_PIN_NEXT_FILE,
        root.as_fd(),
        SOURCE_PIN_FILE,
    )
    .map_err(|error| MountError::State(error.to_string()))?;
    #[cfg(test)]
    if publication_fault == Some(TestPublicationFault::AfterRename) {
        return Err(MountError::State(
            "injected source-pin failure after rename".to_owned(),
        ));
    }
    let directory = rustix::fs::openat(
        root.as_fd(),
        ".",
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| MountError::State(error.to_string()))?;
    rustix::fs::fsync(&directory).map_err(|error| MountError::State(error.to_string()))
}

#[cfg(test)]
fn validate_attestation(
    binding: &SourceRealizationBindingV1,
    attestation: SourcePinAttestationV1,
    identity: FileIdentity,
    mount_id: MountId,
    provider_id: [u8; 16],
    provider_generation: u64,
    kernel_boot_id: [u8; 16],
) -> Result<()> {
    let expected_proof = proof_class_for_binding(binding)?;
    if attestation.binding_digest != binding.digest()
        || attestation.provider_id != provider_id
        || attestation.provider_generation != provider_generation
        || attestation.kernel_boot_id != kernel_boot_id
        || attestation.proof_class != expected_proof
        || identity.file_type != FileType::Directory
        || attestation.device != identity.device
        || attestation.inode != identity.inode
        || attestation.mount_id != mount_id
    {
        return Err(MountError::Worker(
            "source provider attestation does not match the pinned descriptor".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
fn proof_class_for_binding(binding: &SourceRealizationBindingV1) -> Result<SourcePinProofClass> {
    Ok(match binding.consistency() {
        aos_proto::aos::sandbox::local::v1::MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_IMMUTABLE_REVISION => SourcePinProofClass::ImmutableTree,
        aos_proto::aos::sandbox::local::v1::MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_LOCAL_LIVE => SourcePinProofClass::LocalLive,
        aos_proto::aos::sandbox::local::v1::MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_BEST_EFFORT_REPLICA => SourcePinProofClass::BestEffortReplica,
        _ => return Err(MountError::State("source binding has non-native consistency".to_owned())),
    })
}

#[cfg(test)]
fn linux_error(error: aos_sandbox_linux::Error) -> MountError {
    MountError::Worker(error.to_string())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::cell::RefCell;
    use std::collections::BTreeSet;
    use std::os::fd::BorrowedFd;
    use std::rc::Rc;

    use aos_proto::aos::sandbox::local::v1::MountSourceConsistency;
    use aos_sandbox_core::{MediaType, ObjectDescriptor, model::ViewSource};

    use super::*;

    #[derive(Default)]
    struct FakeKeeperState {
        names: BTreeSet<SourcePinName>,
        fail_remove: bool,
        retain_after_remove: bool,
    }

    #[derive(Clone, Default)]
    struct FakeKeeper(Rc<RefCell<FakeKeeperState>>);

    impl SourceDescriptorStore for FakeKeeper {
        fn contains_source(&self, name: &SourcePinName) -> Result<bool> {
            Ok(self.0.borrow().names.contains(name))
        }

        fn store_source(&self, name: &SourcePinName, _descriptor: BorrowedFd<'_>) -> Result<()> {
            self.0.borrow_mut().names.insert(name.clone());
            Ok(())
        }

        fn remove_source(&self, name: &SourcePinName) -> Result<()> {
            let mut state = self.0.borrow_mut();
            if state.fail_remove {
                return Err(MountError::State(
                    "injected keeper removal failure".to_owned(),
                ));
            }
            if !state.retain_after_remove {
                state.names.remove(name);
            }
            Ok(())
        }
    }

    fn binding(byte: u8) -> SourceRealizationBindingV1 {
        SourceRealizationBindingV1::new(
            [byte; 16],
            2,
            ObjectDescriptor::new(
                MediaType::new("application/vnd.aos.sandbox.view.v1+cbor".to_owned()).unwrap(),
                ObjectDigest::from_bytes([3; 32]),
                4,
            ),
            ViewSource::ImmutableTree {
                tree: ObjectDescriptor::new(
                    MediaType::new("application/vnd.aos.sandbox.tree.v1+cbor".to_owned()).unwrap(),
                    ObjectDigest::from_bytes([5; 32]),
                    6,
                ),
            },
            MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_IMMUTABLE_REVISION,
            None,
        )
        .unwrap()
    }

    fn open_source(path: &std::path::Path) -> ResolvedPath {
        let descriptor = rustix::fs::open(
            path,
            rustix::fs::OFlags::PATH
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        ResolvedPath::from_inherited(descriptor).unwrap()
    }

    fn attestation(
        binding: &SourceRealizationBindingV1,
        source: &ResolvedPath,
    ) -> SourcePinAttestationV1 {
        SourcePinAttestationV1 {
            binding_digest: binding.digest(),
            provider_id: [7; 16],
            provider_generation: 8,
            kernel_boot_id: [9; 16],
            device: source.identity().device,
            inode: source.identity().inode,
            mount_id: MountId::from_fd(source.as_fd()).unwrap(),
            proof_class: SourcePinProofClass::ImmutableTree,
        }
    }

    fn trust() -> SourcePinTrustV1 {
        SourcePinTrustV1 {
            provider_id: [7; 16],
            provider_generation: 8,
            kernel_boot_id: [9; 16],
        }
    }

    fn private_directory() -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(
            directory.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        directory
    }

    fn assert_registry_is_poisoned(registry: &mut DurableSourcePins<FakeKeeper>) {
        assert!(registry.resolve(&binding(1)).is_err());
        assert!(
            registry
                .retain(&binding(1), SourcePinReferenceKind::Detached)
                .is_err()
        );
        assert!(registry.reap(&binding(1)).is_err());
    }

    #[test]
    fn predictable_path_without_provider_admission_has_no_authority() {
        let directory = tempfile::tempdir().unwrap();
        let registry = BrokerOwnedSourcePins::new(trust()).unwrap();
        assert!(directory.path().exists());
        assert!(registry.resolve(&binding(1)).is_err());
        assert!(UnavailableSourcePins.resolve(&binding(1)).is_err());
    }

    #[test]
    fn admitted_descriptor_survives_path_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let original = directory.path().join("original");
        std::fs::create_dir(&original).unwrap();
        let source = open_source(&original);
        let attestation = attestation(&binding(1), &source);
        let mut registry = BrokerOwnedSourcePins::new(trust()).unwrap();
        registry.admit(&binding(1), attestation, source).unwrap();

        std::fs::rename(&original, directory.path().join("moved")).unwrap();
        std::fs::create_dir(&original).unwrap();
        let resolved = registry.resolve(&binding(1)).unwrap();
        assert_eq!(resolved.source().identity().inode, attestation.inode);
        assert_ne!(open_source(&original).identity().inode, attestation.inode);

        registry.reap(&binding(1)).unwrap();
        assert!(registry.resolve(&binding(1)).is_err());
    }

    #[test]
    fn provider_substitution_and_equivocation_poison_mutation() {
        let directory = tempfile::tempdir().unwrap();
        let first = open_source(directory.path());
        let first_attestation = attestation(&binding(1), &first);
        let mut registry = BrokerOwnedSourcePins::new(trust()).unwrap();
        let mut wrong_provider = first_attestation;
        wrong_provider.provider_id = [10; 16];
        assert!(
            registry
                .admit(&binding(1), wrong_provider, open_source(directory.path()))
                .is_err()
        );

        registry
            .admit(&binding(1), first_attestation, first)
            .unwrap();
        let other = tempfile::tempdir().unwrap();
        let second = open_source(other.path());
        let mut second_attestation = attestation(&binding(1), &second);
        second_attestation.binding_digest = binding(1).digest();
        assert!(
            registry
                .admit(&binding(1), second_attestation, second)
                .is_err()
        );
        assert!(registry.resolve(&binding(1)).is_err());
    }

    #[test]
    fn provider_generation_is_fixed_across_same_and_distinct_bindings() {
        let directory = tempfile::tempdir().unwrap();
        let mut registry = BrokerOwnedSourcePins::new(trust()).unwrap();

        let first = open_source(directory.path());
        let first_attestation = attestation(&binding(1), &first);
        let mut wrong_initial_generation = first_attestation;
        wrong_initial_generation.provider_generation += 1;
        assert!(
            registry
                .admit(
                    &binding(1),
                    wrong_initial_generation,
                    open_source(directory.path()),
                )
                .is_err()
        );

        registry
            .admit(&binding(1), first_attestation, first)
            .unwrap();
        let mut wrong_same_binding = attestation(&binding(1), &open_source(directory.path()));
        wrong_same_binding.provider_generation += 1;
        assert!(
            registry
                .admit(
                    &binding(1),
                    wrong_same_binding,
                    open_source(directory.path()),
                )
                .is_err()
        );

        let mut wrong_distinct_binding = attestation(&binding(2), &open_source(directory.path()));
        wrong_distinct_binding.provider_generation += 1;
        assert!(
            registry
                .admit(
                    &binding(2),
                    wrong_distinct_binding,
                    open_source(directory.path()),
                )
                .is_err()
        );
        assert!(registry.resolve(&binding(1)).is_ok());
        assert!(registry.resolve(&binding(2)).is_err());
    }

    #[test]
    fn stale_boot_and_binding_substitution_are_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let first = open_source(directory.path());
        let mut stale = attestation(&binding(1), &first);
        stale.kernel_boot_id = [11; 16];
        let mut registry = BrokerOwnedSourcePins::new(trust()).unwrap();
        assert!(registry.admit(&binding(1), stale, first).is_err());

        let second = open_source(directory.path());
        let substituted = attestation(&binding(2), &second);
        assert!(registry.admit(&binding(1), substituted, second).is_err());
    }

    #[test]
    fn readable_directory_descriptor_is_not_an_admissible_source_pin() {
        let directory = tempfile::tempdir().unwrap();
        let readable = rustix::fs::open(
            directory.path(),
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();

        assert!(ResolvedPath::from_inherited(readable).is_err());
        assert_eq!(
            open_source(directory.path()).identity().file_type,
            FileType::Directory
        );
    }

    #[test]
    fn durable_restart_requires_exact_row_name_descriptor_and_reference_counts() {
        let state_root = private_directory();
        let source_root = private_directory();
        let keeper = FakeKeeper::default();
        let source = open_source(source_root.path());
        let initial_attestation = attestation(&binding(1), &source);
        let mut registry = DurableSourcePins::open(
            state_root.path(),
            trust(),
            keeper.clone(),
            BTreeMap::new(),
            RecoveredSourcePinReferencesV1::for_test(BTreeMap::new()),
        )
        .unwrap();
        registry
            .admit(&binding(1), initial_attestation, source)
            .unwrap();
        registry
            .retain(&binding(1), SourcePinReferenceKind::Detached)
            .unwrap();
        let same_source = open_source(source_root.path());
        let same_attestation = attestation(&binding(1), &same_source);
        registry
            .admit(&binding(1), same_attestation, same_source)
            .unwrap();
        drop(registry);

        let name = SourcePinName::from_digest(*binding(1).digest().as_bytes());
        let adopted = BTreeMap::from([(name.clone(), open_source(source_root.path()))]);
        let references = BTreeMap::from([(
            binding(1).digest(),
            SourcePinReferenceCountsV1 {
                detached: 1,
                ..Default::default()
            },
        )]);
        let registry = DurableSourcePins::open(
            state_root.path(),
            trust(),
            keeper.clone(),
            adopted,
            RecoveredSourcePinReferencesV1::for_test(references),
        )
        .unwrap();
        assert!(registry.resolve(&binding(1)).is_ok());
        drop(registry);

        assert!(
            DurableSourcePins::open(
                state_root.path(),
                trust(),
                keeper.clone(),
                BTreeMap::new(),
                RecoveredSourcePinReferencesV1::for_test(BTreeMap::from([(
                    binding(1).digest(),
                    SourcePinReferenceCountsV1 {
                        detached: 1,
                        ..Default::default()
                    }
                )])),
            )
            .is_err()
        );
        let adopted = BTreeMap::from([(name, open_source(source_root.path()))]);
        assert!(
            DurableSourcePins::open(
                state_root.path(),
                trust(),
                keeper,
                adopted,
                RecoveredSourcePinReferencesV1::for_test(BTreeMap::new()),
            )
            .is_err()
        );
    }

    #[test]
    fn durable_snapshot_requires_canonical_bounded_private_json() {
        let state_root = private_directory();
        let source_root = private_directory();
        let keeper = FakeKeeper::default();
        let source = open_source(source_root.path());
        let attestation = attestation(&binding(1), &source);
        let mut registry = DurableSourcePins::open(
            state_root.path(),
            trust(),
            keeper.clone(),
            BTreeMap::new(),
            RecoveredSourcePinReferencesV1::for_test(BTreeMap::new()),
        )
        .unwrap();
        registry.admit(&binding(1), attestation, source).unwrap();
        drop(registry);

        let snapshot_path = state_root.path().join(SOURCE_PIN_FILE);
        let canonical = std::fs::read(&snapshot_path).unwrap();
        let snapshot: DurableSourcePinSnapshot = serde_json::from_slice(&canonical).unwrap();
        assert_eq!(serde_json::to_vec(&snapshot).unwrap(), canonical);

        let rows = serde_json::to_string(&snapshot.rows).unwrap();
        let reordered = format!(
            "{{\"generation\":{},\"version\":{},\"rows\":{rows}}}",
            snapshot.generation, snapshot.version
        );
        assert_ne!(reordered.as_bytes(), canonical);
        assert_eq!(
            serde_json::from_str::<DurableSourcePinSnapshot>(&reordered).unwrap(),
            snapshot
        );
        std::fs::write(&snapshot_path, reordered).unwrap();
        assert!(
            DurableSourcePins::open(
                state_root.path(),
                trust(),
                keeper.clone(),
                BTreeMap::new(),
                RecoveredSourcePinReferencesV1::for_test(BTreeMap::new()),
            )
            .is_err()
        );

        let mut trailing = canonical.clone();
        trailing.push(b'\n');
        std::fs::write(&snapshot_path, trailing).unwrap();
        assert!(
            DurableSourcePins::open(
                state_root.path(),
                trust(),
                keeper.clone(),
                BTreeMap::new(),
                RecoveredSourcePinReferencesV1::for_test(BTreeMap::new()),
            )
            .is_err()
        );

        std::fs::write(&snapshot_path, &canonical).unwrap();
        std::fs::set_permissions(
            &snapshot_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o644),
        )
        .unwrap();
        assert!(
            DurableSourcePins::open(
                state_root.path(),
                trust(),
                keeper.clone(),
                BTreeMap::new(),
                RecoveredSourcePinReferencesV1::for_test(BTreeMap::new()),
            )
            .is_err()
        );

        std::fs::set_permissions(
            &snapshot_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();
        std::fs::set_permissions(
            state_root.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .unwrap();
        assert!(
            DurableSourcePins::open(
                state_root.path(),
                trust(),
                keeper.clone(),
                BTreeMap::new(),
                RecoveredSourcePinReferencesV1::for_test(BTreeMap::new()),
            )
            .is_err()
        );

        std::fs::set_permissions(
            state_root.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        std::fs::write(&snapshot_path, vec![b' '; MAXIMUM_SOURCE_PIN_BYTES + 1]).unwrap();
        assert!(
            DurableSourcePins::open(
                state_root.path(),
                trust(),
                keeper,
                BTreeMap::new(),
                RecoveredSourcePinReferencesV1::for_test(BTreeMap::new()),
            )
            .is_err()
        );
    }

    #[test]
    fn stale_rows_reject_resealed_proof_class_substitution() {
        let state_root = private_directory();
        let source_root = private_directory();
        let keeper = FakeKeeper::default();
        let source = open_source(source_root.path());
        let attestation = attestation(&binding(1), &source);
        let mut registry = DurableSourcePins::open(
            state_root.path(),
            trust(),
            keeper.clone(),
            BTreeMap::new(),
            RecoveredSourcePinReferencesV1::for_test(BTreeMap::new()),
        )
        .unwrap();
        registry.admit(&binding(1), attestation, source).unwrap();
        drop(registry);

        let snapshot_path = state_root.path().join(SOURCE_PIN_FILE);
        let mut snapshot: DurableSourcePinSnapshot =
            serde_json::from_slice(&std::fs::read(&snapshot_path).unwrap()).unwrap();
        snapshot.rows[0].proof_class = SourcePinProofClass::BestEffortReplica;
        std::fs::write(&snapshot_path, serde_json::to_vec(&snapshot).unwrap()).unwrap();
        keeper.0.borrow_mut().names.clear();

        let error = match DurableSourcePins::open(
            state_root.path(),
            SourcePinTrustV1 {
                provider_generation: 9,
                ..trust()
            },
            keeper,
            BTreeMap::new(),
            RecoveredSourcePinReferencesV1::for_test(BTreeMap::new()),
        ) {
            Ok(_) => panic!("resealed proof substitution unexpectedly reopened"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("proof class"));
    }

    #[test]
    fn tombstone_recovers_a_crash_before_or_after_keeper_removal() {
        let state_root = private_directory();
        let source_root = private_directory();
        let keeper = FakeKeeper::default();
        let source = open_source(source_root.path());
        let attestation = attestation(&binding(1), &source);
        let mut registry = DurableSourcePins::open(
            state_root.path(),
            trust(),
            keeper.clone(),
            BTreeMap::new(),
            RecoveredSourcePinReferencesV1::for_test(BTreeMap::new()),
        )
        .unwrap();
        registry.admit(&binding(1), attestation, source).unwrap();
        keeper.0.borrow_mut().fail_remove = true;
        assert!(registry.reap(&binding(1)).is_err());
        drop(registry);

        keeper.0.borrow_mut().fail_remove = false;
        let name = SourcePinName::from_digest(*binding(1).digest().as_bytes());
        let adopted = BTreeMap::from([(name.clone(), open_source(source_root.path()))]);
        let recovered = DurableSourcePins::open(
            state_root.path(),
            trust(),
            keeper.clone(),
            adopted,
            RecoveredSourcePinReferencesV1::for_test(BTreeMap::new()),
        )
        .unwrap();
        assert!(recovered.resolve(&binding(1)).is_err());
        assert!(!keeper.contains_source(&name).unwrap());
        drop(recovered);

        let reopened = DurableSourcePins::open(
            state_root.path(),
            trust(),
            keeper,
            BTreeMap::new(),
            RecoveredSourcePinReferencesV1::for_test(BTreeMap::new()),
        )
        .unwrap();
        assert!(reopened.resolve(&binding(1)).is_err());
    }

    #[test]
    fn uncertain_publication_poisons_all_current_process_authority() {
        for (fault, renamed) in [
            (TestPublicationFault::BeforeRename, false),
            (TestPublicationFault::AfterRename, true),
        ] {
            let state_root = private_directory();
            let source_root = private_directory();
            let keeper = FakeKeeper::default();
            let source = open_source(source_root.path());
            let attestation = attestation(&binding(1), &source);
            let mut registry = DurableSourcePins::open(
                state_root.path(),
                trust(),
                keeper.clone(),
                BTreeMap::new(),
                RecoveredSourcePinReferencesV1::for_test(BTreeMap::new()),
            )
            .unwrap();
            registry.admit(&binding(1), attestation, source).unwrap();
            registry.publication_fault = Some(fault);

            assert!(
                registry
                    .retain(&binding(1), SourcePinReferenceKind::Detached)
                    .is_err()
            );
            assert_registry_is_poisoned(&mut registry);
            drop(registry);

            let name = SourcePinName::from_digest(*binding(1).digest().as_bytes());
            let adopted = BTreeMap::from([(name, open_source(source_root.path()))]);
            let counts = if renamed {
                BTreeMap::from([(
                    binding(1).digest(),
                    SourcePinReferenceCountsV1 {
                        detached: 1,
                        ..Default::default()
                    },
                )])
            } else {
                BTreeMap::new()
            };
            let reopened = DurableSourcePins::open(
                state_root.path(),
                trust(),
                keeper,
                adopted,
                RecoveredSourcePinReferencesV1::for_test(counts),
            )
            .unwrap();
            assert!(reopened.resolve(&binding(1)).is_ok());
        }
    }

    #[test]
    fn first_admission_crash_resolves_durable_row_or_removes_orphan_custody() {
        for (fault, row_was_renamed) in [
            (TestPublicationFault::BeforeRename, false),
            (TestPublicationFault::AfterRename, true),
        ] {
            let state_root = private_directory();
            let source_root = private_directory();
            let keeper = FakeKeeper::default();
            let source = open_source(source_root.path());
            let attestation = attestation(&binding(1), &source);
            let mut registry = DurableSourcePins::open(
                state_root.path(),
                trust(),
                keeper.clone(),
                BTreeMap::new(),
                RecoveredSourcePinReferencesV1::for_test(BTreeMap::new()),
            )
            .unwrap();
            registry.publication_fault = Some(fault);

            assert!(registry.admit(&binding(1), attestation, source).is_err());
            assert_registry_is_poisoned(&mut registry);
            drop(registry);

            let name = SourcePinName::from_digest(*binding(1).digest().as_bytes());
            let adopted = BTreeMap::from([(name.clone(), open_source(source_root.path()))]);
            let reopened = DurableSourcePins::open(
                state_root.path(),
                trust(),
                keeper.clone(),
                adopted,
                RecoveredSourcePinReferencesV1::for_test(BTreeMap::new()),
            )
            .unwrap();
            assert_eq!(reopened.resolve(&binding(1)).is_ok(), row_was_renamed);
            assert_eq!(keeper.contains_source(&name).unwrap(), row_was_renamed);
        }
    }

    #[test]
    fn generation_overflow_poisons_all_current_process_authority() {
        let state_root = private_directory();
        let source_root = private_directory();
        let keeper = FakeKeeper::default();
        let source = open_source(source_root.path());
        let attestation = attestation(&binding(1), &source);
        let mut registry = DurableSourcePins::open(
            state_root.path(),
            trust(),
            keeper,
            BTreeMap::new(),
            RecoveredSourcePinReferencesV1::for_test(BTreeMap::new()),
        )
        .unwrap();
        registry.admit(&binding(1), attestation, source).unwrap();
        registry.generation = u64::MAX;

        assert!(
            registry
                .retain(&binding(1), SourcePinReferenceKind::Detached)
                .is_err()
        );
        assert_registry_is_poisoned(&mut registry);
    }

    #[test]
    fn references_block_reap_and_provider_or_boot_rollover_never_reuses_a_pin() {
        let state_root = private_directory();
        let source_root = private_directory();
        let keeper = FakeKeeper::default();
        let source = open_source(source_root.path());
        let attestation = attestation(&binding(1), &source);
        let mut registry = DurableSourcePins::open(
            state_root.path(),
            trust(),
            keeper.clone(),
            BTreeMap::new(),
            RecoveredSourcePinReferencesV1::for_test(BTreeMap::new()),
        )
        .unwrap();
        registry.admit(&binding(1), attestation, source).unwrap();
        for kind in [
            SourcePinReferenceKind::Preparing,
            SourcePinReferenceKind::Detached,
            SourcePinReferenceKind::Installed,
            SourcePinReferenceKind::Draining,
        ] {
            registry.retain(&binding(1), kind).unwrap();
            assert!(registry.reap(&binding(1)).is_err());
            registry.release(&binding(1), kind).unwrap();
        }
        registry
            .retain(&binding(1), SourcePinReferenceKind::Detached)
            .unwrap();
        drop(registry);

        let name = SourcePinName::from_digest(*binding(1).digest().as_bytes());
        let adopted = BTreeMap::from([(name.clone(), open_source(source_root.path()))]);
        let recovered_references = BTreeMap::from([(
            binding(1).digest(),
            SourcePinReferenceCountsV1 {
                detached: 1,
                ..Default::default()
            },
        )]);
        let mut stale = DurableSourcePins::open(
            state_root.path(),
            SourcePinTrustV1 {
                provider_generation: 9,
                kernel_boot_id: [10; 16],
                ..trust()
            },
            keeper.clone(),
            adopted,
            RecoveredSourcePinReferencesV1::for_test(recovered_references),
        )
        .unwrap();
        assert!(stale.resolve(&binding(1)).is_err());
        assert!(
            stale
                .retain(&binding(1), SourcePinReferenceKind::Detached)
                .is_err()
        );
        stale
            .release(&binding(1), SourcePinReferenceKind::Detached)
            .unwrap();
        stale.reap(&binding(1)).unwrap();
        assert!(!keeper.contains_source(&name).unwrap());
    }
}
