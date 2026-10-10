//! Checks installed source and original kernel/native facts before reader adoption.
//!
//! The policy receives owning borrowed controls and opaque runtime admissions.
//! It authenticates a private candidate mechanism without issuing a class claim.

use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

use crucible::node_adapters::cnp::{LineageReferenceQualification, OriginalRuntimeLineage};
use crucible_node_contract::{ContentRef, IdSet, NodeDescriptor, ResourceLimits, U64};
use crucible_node_provider::{
    ProviderError, client::OriginalLineageRealization, reference_lineage::LineageSourceGuard,
    reference_service::ReferenceProfile,
};

use super::{native, package::InstalledReaderPackage};

struct OriginalEnrollment {
    provider: u32,
    native: u32,
    limits: ResourceLimits,
    measured: native::Enrollment,
}

/// Retains exact installed profile and original process lifetimes beneath custody.
pub(super) struct InstalledReaderPolicy {
    package: Rc<InstalledReaderPackage>,
    profile: ReferenceProfile,
    original: RefCell<Option<OriginalEnrollment>>,
    windows: RefCell<BTreeMap<u64, (ContentRef, u64)>>,
    maximum_windows: usize,
    negotiated: RefCell<Option<IdSet>>,
    witnesses: RefCell<Vec<serde_json::Value>>,
}

impl InstalledReaderPolicy {
    /// Reserves the fixed source inspector and original window population.
    ///
    /// # Errors
    /// Refuses an unsupported window count or unavailable reservation.
    pub(super) fn new(
        package: Rc<InstalledReaderPackage>,
        profile: ReferenceProfile,
        maximum_windows: usize,
    ) -> Result<Self, ProviderError> {
        if maximum_windows == 0 || maximum_windows > 64 {
            return Err(invalid());
        }
        let mut witnesses = Vec::new();
        witnesses
            .try_reserve_exact(maximum_windows)
            .map_err(|_| invalid())?;
        Ok(Self {
            package,
            profile,
            original: RefCell::new(None),
            windows: RefCell::new(BTreeMap::new()),
            maximum_windows,
            negotiated: RefCell::new(None),
            witnesses: RefCell::new(witnesses),
        })
    }

    /// Copies retained native observations without granting qualification.
    ///
    /// # Errors
    /// Refuses a concurrent borrow of the original witness population.
    pub(super) fn witnesses(&self) -> Result<Vec<serde_json::Value>, ProviderError> {
        self.witnesses
            .try_borrow()
            .map(|originals| originals.clone())
            .map_err(|_| invalid())
    }

    /// Retains the exact original negotiated core, evidence and reader features.
    ///
    /// # Errors
    /// Refuses a changed feature set or unavailable original-state borrow.
    pub(super) fn record_negotiation(&self, features: &IdSet) -> Result<(), ProviderError> {
        let expected = [
            "cnp.control-evidence/1",
            "cnp.core/1",
            "org.andyl.reference.original-input-lineage/1",
        ];
        if !features.iter().map(|feature| feature.as_str()).eq(expected) {
            return Err(invalid());
        }
        let mut retained = self.negotiated.try_borrow_mut().map_err(|_| invalid())?;
        match retained.as_ref() {
            Some(original) if original != features => Err(invalid()),
            Some(_) => Ok(()),
            None => {
                *retained = Some(features.clone());
                Ok(())
            }
        }
    }

    /// Returns original negotiated features under the requested read ceiling.
    ///
    /// # Errors
    /// Refuses absent negotiation, an exceeded ceiling or a conflicting borrow.
    pub(super) fn negotiated_features(&self, maximum: usize) -> Result<IdSet, ProviderError> {
        let retained = self.negotiated.try_borrow().map_err(|_| invalid())?;
        let features = retained
            .as_ref()
            .filter(|features| features.len() <= maximum)
            .ok_or_else(invalid)?;
        Ok(features.clone())
    }

    /// Checks the original descriptor against the regenerated installed profile.
    ///
    /// # Errors
    /// Refuses any changed descriptor field.
    pub(super) fn authenticate_descriptor(
        &self,
        descriptor: &NodeDescriptor,
    ) -> Result<(), ProviderError> {
        if descriptor != &self.profile.descriptor {
            return Err(invalid());
        }
        Ok(())
    }

    /// Remeasures both original groups and their installed native premises.
    ///
    /// # Errors
    /// Refuses missing enrollment, changed kernel or package facts, failed
    /// measurements or absent original feature negotiation.
    pub(super) fn authenticate_enrolled(&self) -> Result<(), ProviderError> {
        let retained = self.original.try_borrow().map_err(|_| invalid())?;
        let retained = retained.as_ref().ok_or_else(invalid)?;
        if native::current(
            &self.package,
            retained.provider,
            retained.native,
            &retained.limits,
            &retained.measured.ready,
        )? != retained.measured
        {
            return Err(invalid());
        }
        self.negotiated_features(3).map(|_| ())
    }

    fn authenticate_profile(&self, actual: &ReferenceProfile) -> Result<(), ProviderError> {
        let expected = &self.profile;
        if actual.descriptor != expected.descriptor
            || actual.implementation != expected.implementation
            || actual.operating_contract != expected.operating_contract
            || actual.capabilities != expected.capabilities
            || actual.guarantees != expected.guarantees
            || actual.owner != expected.owner
            || actual.node_manifest != expected.node_manifest
            || actual.provider_manifest != expected.provider_manifest
            || actual.configuration_ref != expected.configuration_ref
            || actual.content_possession_schema != expected.content_possession_schema
            || actual.contents != expected.contents
        {
            return Err(invalid());
        }
        Ok(())
    }
}

impl LineageReferenceQualification for InstalledReaderPolicy {
    fn authenticate_realization(
        &self,
        guard: &LineageSourceGuard,
        view: &OriginalLineageRealization<'_>,
    ) -> Result<(), ProviderError> {
        self.authenticate_profile(view.profile())?;
        let provider = guard.provider_pid().ok_or_else(invalid)?;
        let native = u32::try_from(view.native_pid().get()).map_err(|_| invalid())?;
        let limits = view.bootstrap().resource_limits.clone();
        let measured = native::enroll(&self.package, provider, view, &limits)?;
        let mut original = self.original.try_borrow_mut().map_err(|_| invalid())?;
        match original.as_ref() {
            Some(retained)
                if retained.provider == provider
                    && retained.native == native
                    && retained.limits == limits
                    && retained.measured == measured =>
            {
                Ok(())
            }
            Some(_) => Err(invalid()),
            None => {
                *original = Some(OriginalEnrollment {
                    provider,
                    native,
                    limits,
                    measured,
                });
                Ok(())
            }
        }
    }

    fn authenticate_window(
        &self,
        original: &OriginalRuntimeLineage<'_>,
    ) -> Result<(), ProviderError> {
        let source = original.source();
        let enrollment = self.original.try_borrow().map_err(|_| invalid())?;
        let retained = enrollment.as_ref().ok_or_else(invalid)?;
        if source.native_pid().get() != u64::from(retained.native)
            || source.native_executable() != &self.package.device().content
            || native::current(
                &self.package,
                retained.provider,
                retained.native,
                &retained.limits,
                &retained.measured.ready,
            )? != retained.measured
        {
            return Err(invalid());
        }

        let stage = source.native_stage();
        let receipt = source.native_receipt();
        stage.validate()?;
        let identity = receipt.identity()?;
        if receipt.stage != stage.identity()?
            || receipt.grant != stage.grant
            || receipt.consumed.len() != stage.entries.len()
            || !receipt.application_parked
            || source.controlled_receipt().grant != stage.grant
            || source.controlled_receipt().output != receipt.output
        {
            return Err(invalid());
        }

        // Independent checksum work uses original byte ranges and opaque runtime
        // payloads. Parsed checksum claims never supply their own expected result.
        let mut checksum = receipt.checksum_before.get();
        for (entry, consumed) in stage.entries.iter().zip(&receipt.consumed) {
            let start = usize::try_from(entry.byte_start.get()).map_err(|_| invalid())?;
            let end = usize::try_from(entry.byte_end.get()).map_err(|_| invalid())?;
            let bytes = stage.input.get(start..end).ok_or_else(invalid)?;
            let payload = original
                .input()
                .payloads()
                .iter()
                .find(|payload| payload.reference == entry.payload)
                .ok_or_else(invalid)?;
            if payload.bytes != bytes
                || consumed.event_index != entry.event_index
                || consumed.byte_start != entry.byte_start
                || consumed.byte_end != entry.byte_end
            {
                return Err(invalid());
            }
            for byte in bytes {
                checksum = checksum.wrapping_mul(257).wrapping_add(u64::from(*byte));
            }
            if checksum != consumed.checksum_after.get() {
                return Err(invalid());
            }
        }
        if receipt.output.checksum.get() != checksum
            || receipt.output.bytes_processed.get() != stage.input.len() as u64
        {
            return Err(invalid());
        }

        let quantum = stage.grant.quantum.get();
        let mut windows = self.windows.try_borrow_mut().map_err(|_| invalid())?;
        if let Some(retained) = windows.get(&quantum) {
            return if retained == &(identity, checksum) {
                Ok(())
            } else {
                Err(invalid())
            };
        }
        if windows.len() >= self.maximum_windows {
            return Err(invalid());
        }
        if quantum == 0 {
            if !windows.is_empty()
                || receipt.previous_closed.is_some()
                || receipt.checksum_before.get() != 0
            {
                return Err(invalid());
            }
        } else {
            let previous = windows.get(&(quantum - 1)).ok_or_else(invalid)?;
            if receipt.previous_closed.as_ref() != Some(&previous.0)
                || receipt.checksum_before.get() != previous.1
            {
                return Err(invalid());
            }
        }
        let evidence = source.measurement_evidence(80, 1024 * 1024)?;
        let hex = |bytes: &[u8]| {
            const DIGITS: &[u8; 16] = b"0123456789abcdef";
            let mut result = String::with_capacity(bytes.len() * 2);
            for byte in bytes {
                result.push(char::from(DIGITS[(byte >> 4) as usize]));
                result.push(char::from(DIGITS[(byte & 15) as usize]));
            }
            result
        };
        let (initialize, ready) = source.native_initialization()?;
        let (close, closed) = source.native_close()?;
        let object_rows = evidence.objects().iter().map(|object| serde_json::json!({"reference":object.reference(),"bytes_hex":hex(object.bytes()),"dependencies":object.dependencies()})).collect::<Vec<_>>();
        let witness = serde_json::json!({
            "schema":"crucible.reference.reader-original-window.v1",
            "node":self.profile.descriptor.id,
            "native_pid":source.native_pid(),"original_start_ticks":source.native_start_ticks(),"executable":source.native_executable(),
            "input":source.input_batch(),"stage":stage,"receipt":receipt,"controlled_receipt":source.controlled_receipt(),
            "stop":source.stop(),"observation":source.observation(),"measurement":source.measurement_reference(),"relation":source.consumption_relation_reference(),
            "initialize_hex":hex(initialize),"ready_wire_hex":hex(ready),"close_hex":hex(close),"closed_wire_hex":hex(closed),
            "objects":object_rows,"external_dependencies":evidence.external_dependencies(),
            "checksum_oracle":U64::new(checksum),"class_accepted":false,
        });
        let mut witnesses = self.witnesses.try_borrow_mut().map_err(|_| invalid())?;
        if witnesses.len() >= self.maximum_windows {
            return Err(invalid());
        }
        witnesses.push(witness);
        windows.insert(quantum, (identity, checksum));
        Ok(())
    }
}

fn invalid() -> ProviderError {
    ProviderError::Correlation("installed reader original source premise differs")
}
