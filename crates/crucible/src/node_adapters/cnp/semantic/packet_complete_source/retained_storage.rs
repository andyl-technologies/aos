//! Combines the actual original Source component observers under one bound.
//!
//! This data walk never asks a retired native Child to become current again.
//! Live Capture, archive validation and fresh restoration each retain their own
//! original authority guards. Node/process, Core and external receiver/Host
//! owners remain distinct rows in the whole allocation conjunction.

use super::super::retained_storage::CnpRetainedStorageReport;
use super::*;
use std::rc::Rc;

/// Reports actual retained Source component layouts and unresolved read owners.
///
/// Shared views are conservatively repeated across component rows. Neither
/// equivalent contents nor an equal serialized label receives alias credit.
/// The report is data and cannot select Capture or authorize native effects.
#[derive(Clone, Debug)]
pub struct PacketCompleteSourceRetainedStorage {
    /// Counts the actual Source Rc, independent underlying Box and own path.
    pub holders: usize,
    /// Counts actual installation/program/coordinator and saved-world backing.
    pub installation: usize,
    /// Counts private boot banks, normalized Values, emitter and Hello owners.
    pub boot_association: usize,
    /// Counts full static bytes/rows and first-sealed lineage/batch owners.
    pub static_lineage: usize,
    /// Counts actual capture/return banks, fullrefs and SDK snapshot metadata.
    pub capture_banks: usize,
    /// Counts actual backend/output preparation and moved SDK association owners.
    pub execution: usize,
    /// Counts the retained typed registry owner and its separate complete archive banks.
    pub registry: usize,
    native_reads: [Option<CnpRetainedStorageReport>; 2],
    known_requested_bytes: usize,
}

impl PacketCompleteSourceRetainedStorage {
    /// Borrows actual underlying-source and preconstruction read observations.
    ///
    /// Each report includes shared executable/read/registrar owners without
    /// following live kernel state. Unresolved owners remain immutable, so a
    /// caller cannot erase an obligation before requesting the complete sum.
    pub fn native_reads(&self) -> &[Option<CnpRetainedStorageReport>; 2] {
        &self.native_reads
    }

    /// Returns the checked known sum, including each read's observed owners.
    pub fn known_requested_bytes(&self) -> usize {
        self.known_requested_bytes
    }

    /// Returns this component sum only when its retained reads have no unknowns.
    ///
    /// The actual node/process/SDK capsule, Core runtime/activation/publication
    /// authorities, receiver group, Host and daemon owners must still be added
    /// by their own original observers. This method closes none of those rows,
    /// compiler/allocator rounding, thread stack or kernel resource accounting.
    ///
    /// # Errors
    /// Refuses an unsupported executable worker or another unresolved actual
    /// owner reported by either retained original read.
    pub fn complete_requested_bytes(&self) -> Result<usize, OperationFailure> {
        for read in self.native_reads.iter().flatten() {
            read.complete_requested_bytes()?;
        }
        Ok(self.known_requested_bytes)
    }
}

impl PacketCompleteSemanticSource {
    /// Observes all supported original Source component storage in one bound.
    ///
    /// Borrows the actual Rc and its retained fields without cloning journals,
    /// serializing replacements, renewing cuts or querying old native liveness.
    /// Refusal preserves every owning slot. Original first-Capture source state
    /// is covered; a populated restoration attempt currently refuses in the
    /// association observer until that later owning class is installed.
    ///
    /// This sum is only the Source row. The whole factory must separately join
    /// actual owning node/process/SDK/executable, Core/Host/receiver and daemon
    /// rows and all simultaneous Capture/archive/restore transients. A returned
    /// value or complete component result is never an allocation permission.
    ///
    /// # Errors
    /// Refuses a foreign creator, busy/missing/unsupported component, changed
    /// actual SDK data owner or a checked combined requested-layout overrun.
    pub fn original_complete_retained_storage_data(
        self: &Rc<Self>,
        maximum: usize,
    ) -> Result<PacketCompleteSourceRetainedStorage, OperationFailure> {
        self.ensure_origin()?;
        let holders = self.original_complete_holder_storage_data(maximum)?;
        self.original_complete_storage_with_holders_data(holders, maximum)
    }

    /// Observes nested backing beneath a separately observed actual Source Rc.
    ///
    /// The owning process counter charges this exact Rc's data/header using its
    /// real allocation identity. This walk excludes only that root allocation;
    /// it retains every existing component and unresolved read-owner obligation.
    /// A borrowed stack instance cannot claim a reconstructed Rc allocation.
    ///
    /// # Errors
    /// Refuses a foreign creator, missing/borrowed or unsupported original owner,
    /// arithmetic overflow, or combined requested storage beyond `maximum`.
    pub(in crate::node_adapters::cnp::semantic) fn original_complete_retained_nested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<PacketCompleteSourceRetainedStorage, OperationFailure> {
        self.ensure_origin()?;
        let holders = self.original_complete_nested_holder_storage_data(maximum)?;
        self.original_complete_storage_with_holders_data(holders, maximum)
    }

    fn original_complete_storage_with_holders_data(
        &self,
        holders: usize,
        maximum: usize,
    ) -> Result<PacketCompleteSourceRetainedStorage, OperationFailure> {
        let installation = self.original_complete_installation_storage_data(maximum)?;
        let boot_association = self.original_complete_boot_association_storage_data(maximum)?;
        let static_lineage = self.original_complete_static_lineage_storage_data(maximum)?;
        let capture_banks = self.original_complete_capture_bank_storage_data(maximum)?;
        let execution = self.original_complete_execution_storage_data(maximum)?;
        let registry = retained_values::sum(
            [
                self.original_extension_registry_storage_data(maximum)?,
                self.original_registry_capture_storage_data(maximum)?,
            ],
            maximum,
        )?;
        let underlying_read = match &self.original {
            CompletePacketOriginal::Producer(source) => {
                source.complete_retained_native_read_storage_data(maximum)?
            }
            CompletePacketOriginal::Reactive(source) => {
                source.complete_retained_native_read_storage_data(maximum)?
            }
        };
        let preconstruction = self
            .preconstruction
            .try_borrow()
            .map_err(|_| refused("retained preconstruction already borrowed"))?;
        let preconstruction_read = preconstruction
            .as_ref()
            .map(|original| original.retained_native_read_storage_data(maximum))
            .transpose()?;
        let native_reads = [underlying_read, preconstruction_read];
        let mut known_requested_bytes = retained_values::sum(
            [
                holders,
                installation,
                boot_association,
                static_lineage,
                capture_banks,
                execution,
                registry,
            ],
            maximum,
        )?;
        for read in native_reads.iter().flatten() {
            known_requested_bytes = retained_values::sum(
                [known_requested_bytes, read.known_requested_bytes()],
                maximum,
            )?;
        }
        self.ensure_origin()?;
        Ok(PacketCompleteSourceRetainedStorage {
            holders,
            installation,
            boot_association,
            static_lineage,
            capture_banks,
            execution,
            registry,
            native_reads,
            known_requested_bytes,
        })
    }
}
