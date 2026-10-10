//! Separates native process allowances from retained outside host owners.
//!
//! Values here check conservation only. A matched backend must supply the
//! amounts from its actual retained owners before the family issuer publishes
//! them; validated arithmetic is neither a source owner nor a native grant.

use crucible_linux_resource::ram_policy::HostResourceVector;

use super::{HostRamAdmissionError, HostRamProcessFamilyPartition};

/// Native and outside subsets of one process's complete retained assignment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostRamProcessNativeAllowance {
    process: HostResourceVector,
    native_resident_bytes: u64,
    native_metadata_bytes: u64,
    outside_resident_bytes: u64,
    outside_metadata_bytes: u64,
}

impl HostRamProcessNativeAllowance {
    /// Checks separately supplied native and outside-owner resident subsets.
    ///
    /// Metadata remains inside residency. Native metadata belongs to the
    /// process's startup `TOTAL`; native residency belongs to its `FULL`.
    /// Outside amounts describe retained host owners, not a sharing discount.
    ///
    /// # Errors
    /// Refuses zero native allowances, overflowing or unequal owner sums, or
    /// metadata outside the same owner's resident subset.
    pub fn new(
        process: HostResourceVector,
        native_resident_bytes: u64,
        native_metadata_bytes: u64,
        outside_resident_bytes: u64,
        outside_metadata_bytes: u64,
    ) -> Result<Self, HostRamAdmissionError> {
        HostRamProcessFamilyPartition::single(process)?;
        if native_resident_bytes == 0
            || native_metadata_bytes == 0
            || native_metadata_bytes > native_resident_bytes
            || outside_metadata_bytes > outside_resident_bytes
            || native_resident_bytes.checked_add(outside_resident_bytes)
                != Some(process.resident_peak_bytes)
            || native_metadata_bytes.checked_add(outside_metadata_bytes)
                != Some(process.metadata_bytes)
        {
            return Err(HostRamAdmissionError::contract(
                "native and retained outside owners do not conserve their process assignment",
            ));
        }
        Ok(Self {
            process,
            native_resident_bytes,
            native_metadata_bytes,
            outside_resident_bytes,
            outside_metadata_bytes,
        })
    }

    /// Returns the complete process assignment containing both owner scopes.
    pub const fn process(self) -> HostResourceVector {
        self.process
    }

    /// Returns native residency after retaining the distinct outside owners.
    pub const fn native_resident_bytes(self) -> u64 {
        self.native_resident_bytes
    }

    /// Returns native metadata inside that process's native resident subset.
    pub const fn native_metadata_bytes(self) -> u64 {
        self.native_metadata_bytes
    }

    /// Returns host residency whose original owner remains outside QEMU.
    pub const fn outside_resident_bytes(self) -> u64 {
        self.outside_resident_bytes
    }

    /// Returns outside metadata inside the retained host resident subset.
    pub const fn outside_metadata_bytes(self) -> u64 {
        self.outside_metadata_bytes
    }
}

/// Checks native subsets against one preconfigured initial and staged family.
///
/// This fixed value carries no CPU handoff, kernel controller or source owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostRamProcessFamilyNativeAllowances {
    initial: HostRamProcessNativeAllowance,
    staged: Option<HostRamProcessNativeAllowance>,
}

impl HostRamProcessFamilyNativeAllowances {
    /// Binds separately checked native subsets to their exact family scopes.
    ///
    /// # Errors
    /// Refuses a missing or extra stage, changed process assignment, overflow,
    /// or a family whose native and outside owners duplicate its outer peak.
    pub fn new(
        family: HostRamProcessFamilyPartition,
        initial: HostRamProcessNativeAllowance,
        staged: Option<HostRamProcessNativeAllowance>,
    ) -> Result<Self, HostRamAdmissionError> {
        if initial.process != family.initial()
            || staged.map(|scope| scope.process) != family.staged()
        {
            return Err(HostRamAdmissionError::contract(
                "native process allowances differ from their configured family scopes",
            ));
        }
        let total = |field: fn(HostRamProcessNativeAllowance) -> u64| {
            field(initial).checked_add(staged.map(field).unwrap_or(0))
        };
        let resident =
            total(HostRamProcessNativeAllowance::native_resident_bytes).and_then(|native| {
                total(HostRamProcessNativeAllowance::outside_resident_bytes)
                    .and_then(|outside| native.checked_add(outside))
            });
        let metadata =
            total(HostRamProcessNativeAllowance::native_metadata_bytes).and_then(|native| {
                total(HostRamProcessNativeAllowance::outside_metadata_bytes)
                    .and_then(|outside| native.checked_add(outside))
            });
        if resident != Some(family.envelope().resident_peak_bytes)
            || metadata != Some(family.envelope().metadata_bytes)
        {
            return Err(HostRamAdmissionError::contract(
                "native family allowances exceed the same original envelope",
            ));
        }
        Ok(Self { initial, staged })
    }

    /// Returns the initial native allowance after reserving the staged scope.
    pub const fn initial(self) -> HostRamProcessNativeAllowance {
        self.initial
    }

    /// Returns the prospective stage without issuing a process or CPU phase.
    pub const fn staged(self) -> Option<HostRamProcessNativeAllowance> {
        self.staged
    }
}

#[cfg(test)]
mod tests;
