//! Retains the two fixed native reservations beneath their actual Main issuer.
//!
//! Reservation identities name the already occupied family. They neither carry
//! an execution generation nor construct credit when copied to a process record.
//! Source and Target execution remain in the separate incarnation journal.
//! Task/CPU ceilings share the existing aggregate parent, and file-size limits
//! remain beneath one physical project quota; two rows are not additive grants.
//!
//! ```text
//! CRUCFAM1 | BE schema1/length256 | cap32 | account u64 | assignment u64
//! two rows: role u32 | zero u32 | identity32 | extent u64 | zero u64
//!           memory u64 | FSIZE u64 | tasks u64 | NOFILE u64 | vCPUs u64
//! ```
// SPDX-License-Identifier: Apache-2.0

use crate::linux_attempt_host::native_account::OriginalNativeAccountCredit;
use crate::spawn::ConfiguredProcessEnvelope;

use super::InstalledProcessPurposeError;

/// Keeps one immutable local ceiling without issuing an execution incarnation.
pub(crate) struct InstalledProcessReservation {
    identity: [u8; 32],
    extent: u64,
    resident_ceiling: u64,
    file_size_ceiling: u64,
    task_ceiling: u64,
    descriptor_ceiling: u64,
    cpu_ceiling: u64,
}

/// Owns both once-occupied reservations inside the already funded roster body.
///
/// Construction follows the actual family debit and monotonic kernel refinement.
/// No constructor accepts encoded material, and no reservation can be cloned.
/// The roster allocation prices this inline body before allocating its Arc.
pub(crate) struct InstalledProcessFamily {
    containing_identity: [u8; 32],
    account_generation: u64,
    assignment_generation: u64,
    reservations: [InstalledProcessReservation; 2],
}

/// Prices bounded hash/basis/candidate copies before the helper frame exists.
///
/// The inline final owner is already included in NativeRoster's actual layout.
/// This separate peak covers constructor temporaries and hash compression
/// overlap; it is a conservative containment model, not a measured stack census.
///
/// # Errors
/// Refuses an unrepresentable fixed constructor peak.
pub(super) fn constructor_extent() -> Result<u64, super::OriginalActorAccountError> {
    std::mem::size_of::<blake3::Hasher>()
        .checked_mul(2)
        .and_then(|bytes| {
            bytes.checked_add(std::mem::size_of::<InstalledProcessFamily>().checked_mul(3)?)
        })
        .and_then(|bytes| bytes.checked_add(2 * 80 + 64 * std::mem::size_of::<u32>()))
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(super::OriginalActorAccountError::Unavailable)
}

impl InstalledProcessFamily {
    /// Retains the fixed split from the same authentic containing credit.
    ///
    /// # Errors
    /// Refuses absent Main custody, inactive issuance, changed containment,
    /// overdrawn resident/descriptor shares, or unusable reservation identities.
    pub(super) fn retain(
        credit: &OriginalNativeAccountCredit,
        account_index: usize,
        account_generation: u64,
        assigned_extent: u64,
        envelope: &ConfiguredProcessEnvelope,
    ) -> Result<Self, InstalledProcessPurposeError> {
        credit.require_original()?;
        let retained = credit
            .original
            .as_ref()
            .ok_or(InstalledProcessPurposeError::Identity)?;
        let normal = retained
            .normal
            .as_ref()
            .ok_or(InstalledProcessPurposeError::Identity)?;
        normal
            .verify_native_preparation(&retained.preparation)
            .map_err(super::OriginalActorAccountError::from)?;
        let basis = retained
            .preparation
            .serialize_original_preparation_basis()
            .map_err(|source| InstalledProcessPurposeError::Original(source.into()))?;
        let mut containing_identity = [0; 32];
        containing_identity.copy_from_slice(&basis[16..48]);

        let assignment_generation = normal
            .assignment_epoch()
            .ok_or(InstalledProcessPurposeError::Identity)?;
        let local = envelope.maximum_resident_bytes();
        let local_descriptors = envelope.maximum_file_descriptors();
        let aggregate = credit.native_parent_readback()?;
        if account_generation == 0
            || containing_identity == [0; 32]
            || local == 0
            || local.checked_mul(2) != Some(assigned_extent)
            || assigned_extent > credit.full_resident_bytes()
            || assigned_extent > credit.total_metadata_bytes()
            || local_descriptors == 0
            || local_descriptors
                .checked_mul(2)
                .is_none_or(|total| total > credit.descriptor_ceiling())
            || local_descriptors > credit.local_descriptor_ceiling()?
            || envelope.maximum_writable_bytes() > credit.full_backing_bytes()
            || u64::from(envelope.maximum_tasks()) > aggregate[4]
            || u64::from(envelope.maximum_vcpus()) * 100_000 > aggregate[2]
        {
            return Err(InstalledProcessPurposeError::Capacity);
        }
        let account_index =
            u64::try_from(account_index).map_err(|_| InstalledProcessPurposeError::Identity)?;
        let reservation = |role: u8| {
            let mut identity = blake3::Hasher::new_derive_key(
                "crucible fixed native process reservation identity",
            );
            identity.update(&containing_identity);
            identity.update(&account_index.to_be_bytes());
            identity.update(&account_generation.to_be_bytes());
            identity.update(&assignment_generation.to_be_bytes());
            identity.update(&[role]);
            InstalledProcessReservation {
                identity: *identity.finalize().as_bytes(),
                extent: local,
                resident_ceiling: local,
                file_size_ceiling: envelope.maximum_writable_bytes(),
                task_ceiling: u64::from(envelope.maximum_tasks()),
                descriptor_ceiling: local_descriptors,
                cpu_ceiling: u64::from(envelope.maximum_vcpus()),
            }
        };
        let reservations = [reservation(0), reservation(1)];
        if reservations.iter().any(|slot| slot.identity == [0; 32])
            || reservations[0].identity == reservations[1].identity
        {
            return Err(InstalledProcessPurposeError::Identity);
        }

        credit.require_original()?;
        Ok(Self {
            containing_identity,
            account_generation,
            // Binding occurs once in each genuinely occupied account generation.
            // Target incarnation reuse does not change that assignment event.
            assignment_generation,
            reservations,
        })
    }

    /// Checks the actual later contract against one historical reservation.
    ///
    /// # Errors
    /// Refuses an unknown reservation or changed local ceilings.
    pub(super) fn verify_envelope(
        &self,
        subdivision: u8,
        envelope: &ConfiguredProcessEnvelope,
    ) -> Result<(), InstalledProcessPurposeError> {
        self.reservations
            .get(usize::from(subdivision))
            .filter(|reservation| reservation.matches_envelope(envelope))
            .ok_or(InstalledProcessPurposeError::Identity)?;
        Ok(())
    }

    /// Checks one incarnation against its fixed reservation and actual Main.
    ///
    /// This checks identity only. It does not replay the issuance operation or
    /// obtain time from its completed Preparation; the caller retains the
    /// incarnation's separately entered operation.
    ///
    /// # Errors
    /// Refuses another account/Main, unknown reservation or changed local limits.
    pub(super) fn verify_incarnation(
        &self,
        account_generation: u64,
        containing_basis: &[u8; 80],
        subdivision: u8,
        assigned_extent: u64,
        envelope: &ConfiguredProcessEnvelope,
    ) -> Result<(), InstalledProcessPurposeError> {
        let reservation = self
            .reservations
            .get(usize::from(subdivision))
            .ok_or(InstalledProcessPurposeError::Identity)?;
        if self.account_generation != account_generation
            || self.assignment_generation == 0
            || self.containing_identity != containing_basis[16..48]
            || reservation.extent.checked_mul(2) != Some(assigned_extent)
            || !reservation.matches_envelope(envelope)
        {
            return Err(InstalledProcessPurposeError::Identity);
        }
        Ok(())
    }

    pub(super) fn source_identity(&self) -> ([u8; 32], [u8; 32], u64) {
        (
            self.containing_identity,
            self.reservations[0].identity,
            self.account_generation,
        )
    }

    /// Emits only the reservations retained by this actual containing owner.
    pub(super) fn encode_corroboration(&self) -> [u8; 256] {
        let mut bytes = [0; 256];
        bytes[..8].copy_from_slice(b"CRUCFAM1");
        bytes[8..12].copy_from_slice(&1_u32.to_be_bytes());
        bytes[12..16].copy_from_slice(&256_u32.to_be_bytes());
        bytes[16..48].copy_from_slice(&self.containing_identity);
        bytes[48..56].copy_from_slice(&self.account_generation.to_be_bytes());
        bytes[56..64].copy_from_slice(&self.assignment_generation.to_be_bytes());
        for (index, reservation) in self.reservations.iter().enumerate() {
            let offset = 64 + index * 96;
            bytes[offset..offset + 4].copy_from_slice(&(index as u32).to_be_bytes());
            bytes[offset + 8..offset + 40].copy_from_slice(&reservation.identity);
            for (relative, value) in [
                (40, reservation.extent),
                (56, reservation.resident_ceiling),
                (64, reservation.file_size_ceiling),
                (72, reservation.task_ceiling),
                (80, reservation.descriptor_ceiling),
                (88, reservation.cpu_ceiling),
            ] {
                bytes[offset + relative..offset + relative + 8]
                    .copy_from_slice(&value.to_be_bytes());
            }
            // Offset48 remains zero: a reservation has no execution generation.
        }
        bytes
    }
}

impl InstalledProcessReservation {
    fn matches_envelope(&self, envelope: &ConfiguredProcessEnvelope) -> bool {
        self.resident_ceiling == envelope.maximum_resident_bytes()
            && self.file_size_ceiling == envelope.maximum_writable_bytes()
            && self.task_ceiling == u64::from(envelope.maximum_tasks())
            && self.descriptor_ceiling == envelope.maximum_file_descriptors()
            && self.cpu_ceiling == u64::from(envelope.maximum_vcpus())
    }
}
