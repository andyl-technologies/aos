//! Combines the actual original Source component observers under one bound.
//!
//! This data walk never asks a retired native Child to become current again.
//! Live Capture, archive validation and fresh restoration each retain their own
//! original authority guards. Node/process, Core and external receiver/Host
//! owners remain distinct rows in the whole allocation conjunction.

use super::super::retained_storage::CnpRetainedStorageReport;
use super::*;
use crate::node_adapters::cnp::semantic::packet_complete_source::storage_error::StorageError;
use std::rc::Rc;

#[derive(Clone, Copy)]
enum PrebirthStoragePurpose {
    Code,
    ReportStartup,
}

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
    /// Observes the actual Source before any native or private-birth attempt.
    ///
    /// The separately installed archive-code factory uses this phase for its
    /// code-selection Sources. Absent capture, registry and static-input banks
    /// have no allocation in this phase; present banks retain their actual
    /// capacities. This never clears an unresolved live ownership report.
    /// External receiver, Host, factory and code-graph owners remain separate.
    ///
    /// # Errors
    /// Refuses foreign creation custody, any spent launch/private birth/native
    /// association, a busy owner, unsupported retained backing or the bound.
    pub fn original_complete_code_retained_storage_data(
        self: &Rc<Self>,
        maximum: usize,
    ) -> Result<usize, OperationFailure> {
        self.original_prebirth_storage_data(PrebirthStoragePurpose::Code, maximum)
    }

    /// Observes actual pre-Child owners beneath an unstarted original private birth.
    ///
    /// This counts the existing key/birth banks and all present Source banks.
    /// The installed policy must separately admit prospective report, prefix,
    /// ACK/error and counter owners before finalizing the private boot. A
    /// successful observation is data and cannot issue that admission.
    ///
    /// # Errors
    /// Refuses another creator, missing/failed/started private birth, any launch
    /// or native-association attempt, unsupported backing or the supplied bound.
    pub fn original_complete_report_startup_retained_storage_data(
        self: &Rc<Self>,
        maximum: usize,
    ) -> Result<usize, OperationFailure> {
        self.original_prebirth_storage_data(PrebirthStoragePurpose::ReportStartup, maximum)
    }

    fn authenticate_prebirth_storage_phase_with_error<
        E: crate::node_adapters::cnp::semantic::packet_complete_source::storage_error::StorageError,
    >(
        &self,
        purpose: PrebirthStoragePurpose,
    ) -> Result<(), E> {
        // Creator checks precede all interior loans. A dropped reservation
        // cannot erase its spent launch flag and reopen the pre-Child phase.
        self.storage_origin_with_error::<E>()?;
        if self.complete_bytes_launch_reserved.get()
            || self.registry_retention_attempted.get()
            || self.registry_retention_failed.get()
            || self
                .preconstruction
                .try_borrow()
                .map_err(E::unknown)?
                .is_some()
            || self
                .original_extension_registry
                .try_borrow()
                .map_err(E::unknown)?
                .is_some()
        {
            return Err(E::refused(
                "original Source is outside its pre-Child storage phase",
            ));
        }
        let unbound = match &self.original {
            CompletePacketOriginal::Producer(source) => {
                source.complete_preparation_unbound_with_error::<E>()?
            }
            CompletePacketOriginal::Reactive(source) => {
                source.complete_preparation_unbound_with_error::<E>()?
            }
        };
        if !unbound {
            return Err(E::refused(
                "pre-Child Source already has original native custody",
            ));
        }
        let birth = self.ack_peer_birth.try_borrow().map_err(E::unknown)?;
        match purpose {
            PrebirthStoragePurpose::Code => {
                if self.ack_birth_attempted
                    || birth.is_some()
                    || self
                        .ack_peer_association
                        .try_borrow()
                        .map_err(E::unknown)?
                        .is_some()
                {
                    return Err(E::refused(
                        "archive code Source has attempted private birth",
                    ));
                }
            }
            PrebirthStoragePurpose::ReportStartup => {
                if !self.ack_birth_attempted {
                    return Err(E::refused(
                        "report startup Source has no original private birth",
                    ));
                }
                birth
                    .as_ref()
                    .ok_or_else(|| E::refused("report startup private birth is absent"))?
                    .authenticate_unstarted_storage_phase_with_error::<E>()?;
                self.ack_peer_association
                    .try_borrow()
                    .map_err(E::unknown)?
                    .as_ref()
                    .ok_or_else(|| E::refused("report startup reserved ACK banks are absent"))?
                    .authenticate_reserved_prebirth_data_with_error::<E>()?;
            }
        }
        Ok(())
    }

    fn original_prebirth_storage_data(
        self: &Rc<Self>,
        purpose: PrebirthStoragePurpose,
        maximum: usize,
    ) -> Result<usize, OperationFailure> {
        self.original_prebirth_storage_data_with_error::<OperationFailure>(purpose, maximum)
    }

    fn original_prebirth_storage_data_with_error<
        E: crate::node_adapters::cnp::semantic::packet_complete_source::storage_error::StorageError,
    >(
        self: &Rc<Self>,
        purpose: PrebirthStoragePurpose,
        maximum: usize,
    ) -> Result<usize, E> {
        self.authenticate_prebirth_storage_phase_with_error::<E>(purpose)?;
        let holders = self.original_complete_holder_storage_data_with_error::<E>(maximum)?;
        let installation =
            self.original_complete_installation_storage_data_with_error::<E>(maximum)?;
        let boot = self.original_complete_boot_association_storage_data_with_error::<E>(maximum)?;
        let lineage = match &self.original {
            CompletePacketOriginal::Producer(_) => 0,
            CompletePacketOriginal::Reactive(source) => retained_values::sum_with_error::<E, _>(
                [
                    source.complete_prebirth_input_static_storage_with_error::<E>(maximum)?,
                    source.complete_retained_lineage_storage_with_error::<E>(maximum)?,
                ],
                maximum,
            )?,
        };

        // Only this explicit unlaunched phase accepts an actually absent bank.
        // The live complete observer keeps its existing mandatory-bank checks.
        let capture = if self
            .capture_banks
            .try_borrow()
            .map_err(E::unknown)?
            .is_some()
        {
            self.original_complete_capture_bank_storage_data_with_error::<E>(maximum)?
        } else {
            0
        };
        let execution = self.original_complete_execution_storage_data_with_error::<E>(maximum)?;
        let registry = self.original_registry_capture_storage_data_with_error::<E>(maximum)?;
        let total = retained_values::sum_with_error::<E, _>(
            [
                holders,
                installation,
                boot,
                lineage,
                capture,
                execution,
                registry,
            ],
            maximum,
        )?;
        self.authenticate_prebirth_storage_phase_with_error::<E>(purpose)?;
        Ok(total)
    }

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
        self.original_complete_storage_with_holders_data_with_error::<OperationFailure>(
            holders, maximum,
        )
    }

    pub(in crate::node_adapters::cnp::semantic) fn original_complete_storage_with_holders_data_with_error<
        E: StorageError,
    >(
        &self,
        holders: usize,
        maximum: usize,
    ) -> Result<PacketCompleteSourceRetainedStorage, E> {
        let installation =
            self.original_complete_installation_storage_data_with_error::<E>(maximum)?;
        let boot_association =
            self.original_complete_boot_association_storage_data_with_error::<E>(maximum)?;
        let static_lineage =
            self.original_complete_static_lineage_storage_data_with_error::<E>(maximum)?;
        let capture_banks =
            self.original_complete_capture_bank_storage_data_with_error::<E>(maximum)?;
        let execution = self.original_complete_execution_storage_data_with_error::<E>(maximum)?;
        let registry = retained_values::sum_with_error::<E, _>(
            [
                self.original_extension_registry_storage_data_with_error::<E>(maximum)?,
                self.original_registry_capture_storage_data_with_error::<E>(maximum)?,
            ],
            maximum,
        )?;
        let underlying_read = match &self.original {
            CompletePacketOriginal::Producer(source) => {
                source.complete_retained_native_read_storage_data_with_error::<E>(maximum)?
            }
            CompletePacketOriginal::Reactive(source) => {
                source.complete_retained_native_read_storage_data_with_error::<E>(maximum)?
            }
        };
        let preconstruction = self
            .preconstruction
            .try_borrow()
            .map_err(|_| E::refused("retained preconstruction already borrowed"))?;
        let preconstruction_read = preconstruction
            .as_ref()
            .map(|original| original.retained_native_read_storage_data_with_error::<E>(maximum))
            .transpose()?;
        let native_reads = [underlying_read, preconstruction_read];
        let mut known_requested_bytes = retained_values::sum_with_error::<E, _>(
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
            known_requested_bytes = retained_values::sum_with_error::<E, _>(
                [known_requested_bytes, read.known_requested_bytes()],
                maximum,
            )?;
        }
        self.storage_origin_with_error::<E>()?;
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

#[cfg(test)]
#[path = "retained_storage/prebirth_tests.rs"]
mod prebirth_tests;

impl PacketCompleteSourceRetainedStorage {
    pub(in crate::node_adapters::cnp::semantic) fn complete_requested_bytes_precredit_data(
        &self,
    ) -> Result<usize, crate::node_contract::RuntimeError> {
        for read in self.native_reads.iter().flatten() {
            read.complete_requested_bytes_precredit_data()?;
        }
        Ok(self.known_requested_bytes)
    }
}

impl PacketCompleteSemanticSource {
    pub(in crate::node_adapters::cnp::semantic) fn original_complete_retained_nested_precredit_data(
        &self,
        maximum: usize,
    ) -> Result<usize, crate::node_contract::RuntimeError> {
        use crate::node_contract::RuntimeError;

        self.storage_origin_with_error::<RuntimeError>()?;
        let holders =
            self.original_complete_nested_holder_storage_data_with_error::<RuntimeError>(maximum)?;
        self.original_complete_storage_with_holders_data_with_error::<RuntimeError>(
            holders, maximum,
        )?
        .complete_requested_bytes_precredit_data()
    }
}

impl PacketCompleteSemanticSource {
    /// Observes actual never-born code selection owners with raw failures.
    ///
    /// # Errors
    /// Refuses foreign, spent, associated, unsupported or over-bound owners.
    pub fn original_complete_code_retained_storage_precredit_data(
        self: &Rc<Self>,
        maximum: usize,
    ) -> Result<usize, crate::node_contract::RuntimeError> {
        self.original_prebirth_storage_data_with_error::<crate::node_contract::RuntimeError>(
            PrebirthStoragePurpose::Code,
            maximum,
        )
    }

    /// Observes actual ready and unstarted private-birth owners with raw failures.
    ///
    /// # Errors
    /// Refuses foreign, absent, failed, started, associated or over-bound owners.
    pub fn original_complete_report_startup_retained_storage_precredit_data(
        self: &Rc<Self>,
        maximum: usize,
    ) -> Result<usize, crate::node_contract::RuntimeError> {
        self.original_prebirth_storage_data_with_error::<crate::node_contract::RuntimeError>(
            PrebirthStoragePurpose::ReportStartup,
            maximum,
        )
    }
}

#[cfg(test)]
#[path = "retained_storage/prebirth_precredit_tests.rs"]
mod prebirth_precredit_tests;
