//! Observes concrete CNP owners without copying their state or granting authority.
//!
//! An observation reports actual retained capacities. Unknown erased supervisor
//! and executable-worker owners remain explicit; a partial sum cannot satisfy a
//! complete admission. Source-private objects and owning Core runtime banks are
//! separate rows, even when this capsule retains an alias to them.

use std::{
    collections::BTreeMap,
    fs::File,
    mem::{align_of, align_of_val, size_of, size_of_val},
    path::PathBuf,
    rc::Rc,
};

use crucible_node_format::{ContentRef, HashRef, Id};

use crate::node_contract::{NodeRuntime, OperationFailure};

use super::{CnpSemanticNode, PacketCompleteSemanticSource, refused, unknown};

pub(super) mod common;
pub(super) mod preparation;
pub use preparation::CnpPreparationStorageScratch;

/// Identifies backing whose actual owner still needs a separate typed observer.
///
/// These flags are obligations, not zero-byte estimates. They neither classify
/// native completion nor permit a changed owner to replace an original one.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CnpRetainedStorageUnknowns {
    /// The independent supervisor slot contains an erased owning implementation.
    pub supervisor_slot: bool,
    /// The protocol supervisor retains an erased callback without a typed data loan.
    pub protocol_supervisor_callback: bool,
    /// Tuple metadata has no exhaustive actual live SDK reader/stream/root observer.
    pub live_sdk_backing: bool,
    /// An acquired executable lease retains private thread/channel backing.
    pub executable_lease_worker: bool,
    /// The selected build has not bound the audited std Child layout contract.
    pub child_process_backing: bool,
    /// Child standard-stream owners have unsupported private library backing.
    pub child_streams: bool,
    /// A retained extension handshake owns an erased installed callback.
    pub extension_callback: bool,
    /// Installed policy and Source backings need their distinct typed owners.
    pub installed_source_owners: bool,
}

impl CnpRetainedStorageUnknowns {
    fn is_empty(self) -> bool {
        self == Self::default()
    }
}

/// Reports one borrowed original CNP owner's requested userspace storage observation.
///
/// The known sum includes actual root layouts, capacities and supported shared
/// owners. It excludes kernel tables, allocation rounding, callback/transient
/// stack and the enclosing runtime's own storage. Equal bytes never identify an
/// allocation. Independent shared views may be conservatively counted again.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CnpRetainedStorageReport {
    known_requested_bytes: usize,
    unknowns: CnpRetainedStorageUnknowns,
    std_child_layout: bool,
}

impl CnpRetainedStorageReport {
    /// Returns the checked sum of observed concrete owners, including spare space.
    pub fn known_requested_bytes(&self) -> usize {
        self.known_requested_bytes
    }

    /// Returns every unresolved owner encountered by the same borrowed walk.
    pub fn unknowns(&self) -> CnpRetainedStorageUnknowns {
        self.unknowns
    }

    /// Names the audited candidate contract matching the observed Child shape.
    ///
    /// This does not authenticate its compiler product or close the corresponding
    /// unknown. The selected implementation's qualification must bind the exact
    /// audited producer, target and std sources. Kernel resources and spawn
    /// transients remain separate even after that independent qualification.
    pub fn candidate_std_child_layout_contract(&self) -> Option<&'static str> {
        self.std_child_layout
            .then_some("aos.rust-1.98.1.gnu-linux.child-unretained-stdio/1")
    }

    /// Returns a complete row only when every retained owner is supported.
    ///
    /// # Errors
    /// Refuses any unresolved supervisor, worker, callback or installed owner.
    pub fn complete_requested_bytes(&self) -> Result<usize, OperationFailure> {
        if !self.unknowns.is_empty() {
            return Err(refused(
                "original CNP requested-storage ownership is incomplete",
            ));
        }
        Ok(self.known_requested_bytes)
    }
}

const SHARED_LIMIT: usize = 256;

#[derive(Clone, Copy)]
struct SharedOwner {
    identity: *const (),
    bytes: usize,
}

pub(super) struct Counter {
    bytes: usize,
    maximum: usize,
    shared: [Option<SharedOwner>; SHARED_LIMIT],
    used: usize,
    json_nodes: usize,
    pub(super) unknowns: CnpRetainedStorageUnknowns,
    pub(super) std_child_layout: bool,
}

impl Counter {
    pub(super) fn new(maximum: usize) -> Self {
        Self {
            bytes: 0,
            maximum,
            shared: [None; SHARED_LIMIT],
            used: 0,
            json_nodes: 0,
            unknowns: CnpRetainedStorageUnknowns::default(),
            std_child_layout: false,
        }
    }

    pub(super) fn finish(self) -> CnpRetainedStorageReport {
        CnpRetainedStorageReport {
            known_requested_bytes: self.bytes,
            unknowns: self.unknowns,
            std_child_layout: self.std_child_layout,
        }
    }

    pub(super) fn remaining(&self) -> usize {
        self.maximum - self.bytes
    }

    pub(super) fn ceiling(&self) -> usize {
        self.maximum
    }

    pub(super) fn add(&mut self, bytes: usize) -> Result<(), OperationFailure> {
        let next = self
            .bytes
            .checked_add(bytes)
            .filter(|next| *next <= self.maximum)
            .ok_or_else(exhausted)?;
        self.bytes = next;
        Ok(())
    }

    pub(super) fn charge(&mut self, value: &impl Owned) -> Result<(), OperationFailure> {
        value.charge(self)
    }

    pub(super) fn metadata(
        &mut self,
        facts: &crucible_node_transport::protocol_snapshot::RetainedProtocolMetadataFacts,
    ) -> Result<(), OperationFailure> {
        self.add(
            PacketCompleteSemanticSource::complete_retained_metadata_storage_data(
                facts,
                self.remaining(),
            )?,
        )
    }

    /// Admits an actual shared allocation descriptor once, without following it.
    pub(super) fn shared(
        &mut self,
        identity: *const (),
        bytes: usize,
    ) -> Result<bool, OperationFailure> {
        if identity.is_null() {
            return Err(refused("original CNP shared allocation identity is absent"));
        }
        for owner in self.shared[..self.used].iter().flatten() {
            if owner.identity == identity {
                if owner.bytes != bytes {
                    return Err(refused("original CNP shared allocation layout changed"));
                }
                return Ok(false);
            }
        }
        if self.used == self.shared.len() {
            return Err(exhausted());
        }
        self.add(bytes)?;
        self.shared[self.used] = Some(SharedOwner { identity, bytes });
        self.used += 1;
        Ok(true)
    }

    pub(super) fn rc<T: ?Sized>(&mut self, value: &Rc<T>) -> Result<bool, OperationFailure> {
        self.shared_layout(
            Rc::as_ptr(value).cast(),
            size_of_val(value.as_ref()),
            align_of_val(value.as_ref()),
        )
    }

    pub(super) fn shared_layout(
        &mut self,
        identity: *const (),
        inline: usize,
        alignment: usize,
    ) -> Result<bool, OperationFailure> {
        let header =
            NodeRuntime::capture_protocol_shared_header_storage(1, alignment, self.maximum)
                .map_err(unknown)?;
        let bytes = inline.checked_add(header).ok_or_else(exhausted)?;
        self.shared(identity, bytes)
    }

    pub(super) fn arc_file(&mut self, file: &File) -> Result<(), OperationFailure> {
        // LinuxReadLeaseFile retains this exact Arc<File> data allocation. An
        // independent open of the same inode receives a different identity.
        self.shared_layout(
            std::ptr::from_ref(file).cast(),
            size_of::<File>(),
            align_of::<File>(),
        )?;
        Ok(())
    }

    pub(super) fn tree<K, V>(&mut self, map: &BTreeMap<K, V>) -> Result<(), OperationFailure> {
        let entry = size_of::<K>()
            .checked_add(size_of::<V>())
            .ok_or_else(exhausted)?;
        self.add(
            NodeRuntime::capture_protocol_tree_storage(
                1,
                map.len(),
                entry,
                align_of::<K>().max(align_of::<V>()),
                self.remaining(),
            )
            .map_err(unknown)?,
        )
    }

    pub(super) fn extensions(
        &mut self,
        values: &crucible_node_format::Extensions,
    ) -> Result<(), OperationFailure> {
        self.tree(values)?;
        for (key, value) in values {
            self.charge(key)?;
            self.json(value, 0)?;
        }
        Ok(())
    }

    fn json(&mut self, value: &serde_json::Value, depth: usize) -> Result<(), OperationFailure> {
        self.json_nodes = self.json_nodes.checked_add(1).ok_or_else(exhausted)?;
        if depth > 64 || self.json_nodes > 1_000_000 {
            return Err(refused("original CNP JSON owner traversal is unsupported"));
        }
        match value {
            serde_json::Value::String(value) => self.charge(value)?,
            serde_json::Value::Array(values) => {
                self.add(
                    values
                        .capacity()
                        .checked_mul(size_of::<serde_json::Value>())
                        .ok_or_else(exhausted)?,
                )?;
                for value in values {
                    self.json(value, depth + 1)?;
                }
            }
            serde_json::Value::Object(values) => {
                // The pinned default/std serde_json Map owns a BTreeMap and
                // Number is inline; preserve_order/arbitrary_precision are not
                // part of this source cohort or its requested-layout contract.
                let entry = size_of::<String>()
                    .checked_add(size_of::<serde_json::Value>())
                    .ok_or_else(exhausted)?;
                self.add(
                    NodeRuntime::capture_protocol_tree_storage(
                        1,
                        values.len(),
                        entry,
                        align_of::<String>().max(align_of::<serde_json::Value>()),
                        self.remaining(),
                    )
                    .map_err(unknown)?,
                )?;
                for (key, value) in values {
                    self.charge(key)?;
                    self.json(value, depth + 1)?;
                }
            }
            serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {
            }
        }
        Ok(())
    }
}

pub(super) trait Owned {
    fn charge(&self, counter: &mut Counter) -> Result<(), OperationFailure>;
}

impl Owned for Id {
    fn charge(&self, counter: &mut Counter) -> Result<(), OperationFailure> {
        counter.add(self.allocated_capacity())
    }
}

impl Owned for String {
    fn charge(&self, counter: &mut Counter) -> Result<(), OperationFailure> {
        counter.add(self.capacity())
    }
}

impl Owned for PathBuf {
    fn charge(&self, counter: &mut Counter) -> Result<(), OperationFailure> {
        counter.add(self.capacity())
    }
}

impl Owned for HashRef {
    fn charge(&self, counter: &mut Counter) -> Result<(), OperationFailure> {
        let Self {
            algorithm,
            domain,
            digest,
        } = self;
        counter.charge(algorithm)?;
        counter.charge(domain)?;
        counter.charge(digest)
    }
}

impl Owned for ContentRef {
    fn charge(&self, counter: &mut Counter) -> Result<(), OperationFailure> {
        let Self {
            hash,
            length: _,
            media_type,
        } = self;
        counter.charge(hash)?;
        counter.charge(media_type)
    }
}

impl<T: Owned> Owned for Vec<T> {
    fn charge(&self, counter: &mut Counter) -> Result<(), OperationFailure> {
        counter.add(
            self.capacity()
                .checked_mul(size_of::<T>())
                .ok_or_else(exhausted)?,
        )?;
        for value in self {
            counter.charge(value)?;
        }
        Ok(())
    }
}

impl Owned for u8 {
    fn charge(&self, _: &mut Counter) -> Result<(), OperationFailure> {
        Ok(())
    }
}

impl<T: Owned> Owned for Option<T> {
    fn charge(&self, counter: &mut Counter) -> Result<(), OperationFailure> {
        if let Some(value) = self {
            counter.charge(value)?;
        }
        Ok(())
    }
}

impl Owned for crate::node_scheduling::InputPayload {
    fn charge(&self, counter: &mut Counter) -> Result<(), OperationFailure> {
        let Self { reference, bytes } = self;
        counter.charge(reference)?;
        counter.add(bytes.capacity())
    }
}

fn exhausted() -> OperationFailure {
    refused("original CNP requested-storage ceiling or traversal bank exhausted")
}

impl CnpSemanticNode {
    /// Observes this same original node's concrete common, SDK and process owners.
    ///
    /// No serializer, source callback, kernel query or native operation runs.
    /// This lends actual immutable originals only. Separate Source and Core
    /// owners, worker/slot backing and physical/transient storage remain required.
    ///
    /// # Errors
    /// Refuses foreign process/thread custody, missing originals, mutable loans,
    /// unsupported typed metadata, arithmetic overflow or the supplied ceiling.
    pub fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<CnpRetainedStorageReport, OperationFailure> {
        self.observe_retained_storage_data(None, maximum)
    }

    /// Observes the same node with its original SDK-known registry owner loan.
    ///
    /// The borrowed owner must authenticate against the exact retained extension
    /// handshake. It supplies metadata only; no caller-created registry object,
    /// decoded selection or callback acceptance replaces that original custody.
    ///
    /// # Errors
    /// Refuses another registry/handshake, foreign custody or unsupported owners
    /// and bounds under the same rules as the ordinary data observation.
    pub fn retained_requested_storage_with_registry_data(
        &self,
        registry: &crucible_node_transport::handshake::OriginalExtensionRegistryOwner,
        maximum: usize,
    ) -> Result<CnpRetainedStorageReport, OperationFailure> {
        self.observe_retained_storage_data(Some(registry), maximum)
    }

    fn observe_retained_storage_data(
        &self,
        registry: Option<&crucible_node_transport::handshake::OriginalExtensionRegistryOwner>,
        maximum: usize,
    ) -> Result<CnpRetainedStorageReport, OperationFailure> {
        // The selected original conversion retains its genuine registry and
        // supervisor witnesses through type erasure. Reuse the complete raw
        // owning walk for that dormant family, without dropping those roots.
        // Existing ordinary nodes keep their original observer path below.
        if self.retained_registry.is_some() || self.retained_supervisor.is_some() {
            let scratch = preparation::CnpPreparationStorageScratch::new(
                preparation::CnpPreparationStorageScratch::requested_bytes(),
            )
            .map_err(unknown)?;
            return self
                .original_retained_node_precredit_data(
                    &scratch,
                    registry,
                    self.retained_supervisor.as_ref(),
                    maximum,
                )
                .map_err(unknown);
        }
        self.preparation.guard.storage_origin_data()?;
        if !self.affinity.permits_current_thread() {
            return Err(refused(
                "original CNP node storage belongs to another thread",
            ));
        }
        let mut counter = Counter::new(maximum);
        counter.add(size_of::<Self>())?;
        counter.add(
            NodeRuntime::capture_route_storage_data(&self.route, counter.remaining())
                .map_err(unknown)?,
        )?;
        counter.charge(&self.exact_profile)?;
        common::preparation(&self.preparation, registry, &mut counter)?;
        self.preparation.guard.storage_origin_data()?;
        Ok(counter.finish())
    }
}

impl super::CnpSemanticConformanceNode {
    /// Observes this original collecting capsule through its actual inner node.
    ///
    /// The wrapper's actual additional inline storage is counted independently;
    /// no assumed transparent layout or copied common snapshot is substituted.
    /// This method grants no collecting, capture or ordinary node permission.
    ///
    /// # Errors
    /// Refuses foreign owners, unsupported layouts, an incomplete typed walk or
    /// requested storage beyond the supplied maximum.
    pub fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<CnpRetainedStorageReport, OperationFailure> {
        let extra = size_of::<Self>()
            .checked_sub(size_of::<CnpSemanticNode>())
            .ok_or_else(exhausted)?;
        let available = maximum.checked_sub(extra).ok_or_else(exhausted)?;
        let mut report = self.0.retained_requested_storage_data(available)?;
        report.known_requested_bytes = report
            .known_requested_bytes
            .checked_add(extra)
            .ok_or_else(exhausted)?;
        Ok(report)
    }

    /// Observes the collecting capsule with the same original SDK registry loan.
    ///
    /// # Errors
    /// Refuses another original registry, foreign owners, unsupported metadata,
    /// checked layout overflow or requested storage beyond the supplied maximum.
    pub fn retained_requested_storage_with_registry_data(
        &self,
        registry: &crucible_node_transport::handshake::OriginalExtensionRegistryOwner,
        maximum: usize,
    ) -> Result<CnpRetainedStorageReport, OperationFailure> {
        let extra = size_of::<Self>()
            .checked_sub(size_of::<CnpSemanticNode>())
            .ok_or_else(exhausted)?;
        let available = maximum.checked_sub(extra).ok_or_else(exhausted)?;
        let mut report = self
            .0
            .retained_requested_storage_with_registry_data(registry, available)?;
        report.known_requested_bytes = report
            .known_requested_bytes
            .checked_add(extra)
            .ok_or_else(exhausted)?;
        Ok(report)
    }
}

#[cfg(test)]
mod tests;

pub(super) struct StorageOrigin {
    process: u32,
    thread: std::thread::ThreadId,
}

impl StorageOrigin {
    pub(super) fn check_precredit_data(&self) -> Result<(), crate::node_contract::RuntimeError> {
        if self.process != std::process::id() {
            return Err(crate::node_contract::RuntimeError::ForeignAuthority);
        }
        if self.thread != std::thread::current().id() {
            return Err(crate::node_contract::RuntimeError::ThreadAffinity);
        }
        Ok(())
    }

    pub(super) fn current() -> Self {
        Self {
            process: std::process::id(),
            thread: std::thread::current().id(),
        }
    }

    pub(super) fn check(&self) -> Result<(), OperationFailure> {
        if self.process != std::process::id() || self.thread != std::thread::current().id() {
            return Err(refused("original CNP metadata belongs to another creator"));
        }
        Ok(())
    }
}
