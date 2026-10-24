//! Checks the actual inactive lifecycle for the selected fresh query route.
//!
//! No portable label or hash substitutes for these same Control owners. The
//! endpoint separately authenticates private boot/ACK purpose and both grants.

use super::*;

impl PacketControl {
    pub(crate) fn authenticate_original_fresh_admission_data(
        &self,
        policy: &super::super::Native5Policy,
        admission: &str,
    ) -> Result<(), ProviderError> {
        if !self.original_fresh_report_window_data()? {
            return Err(ProviderError::Correlation(
                "fresh report Control is not admitted",
            ));
        }
        policy.authenticate_original_control_selection(&self.selection)?;
        if self.selection.admission.as_str() != admission {
            return Err(ProviderError::Correlation(
                "fresh report actual admission differs",
            ));
        }
        Ok(())
    }

    pub(crate) fn original_fresh_report_window_data(&self) -> Result<bool, ProviderError> {
        if self.capture_creator != std::process::id() {
            return Err(ProviderError::Correlation("fresh report foreign Control"));
        }
        // Baseline Discover/Realize/Admit still reach their original dispatcher.
        if !self.realized || !self.admitted {
            return Ok(false);
        }
        if self.fenced
            || self.native_effect_attempted
            || self.active.is_some()
            || self.staged.is_some()
            || self.current_operation.is_some()
            || !self.begins.is_empty()
            || !self.begin_requests.is_empty()
            || !self.terminals.is_empty()
            || self.complete_restored_hold.is_some()
            || self.complete_restored_evidence.is_some()
            || self.common_coordinator.is_some()
            || self.world_coordinator.is_some()
            || self.connected_coordinator.is_some()
            || self.complete_coordinator.is_none()
        {
            return Err(ProviderError::Correlation(
                "fresh report Control already used",
            ));
        }
        Ok(true)
    }
}

impl PacketControl {
    /// Walks this actual inactive Control/model without creating a currency clone.
    pub(crate) fn observe_original_fresh_report_metadata(
        &self,
        policy: &super::super::Native5Policy,
        roots: &mut crate::retained_metadata::NativeCaptureMetadataRoots,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), ProviderError> {
        if !self.original_fresh_report_window_data()? {
            return Err(ProviderError::Correlation(
                "fresh Control census before Admit",
            ));
        }
        policy.authenticate_original_control_selection(&self.selection)?;
        let Self {
            selection,
            program,
            complete_restored_evidence,
            complete_restored_hold,
            restoration_activation_required,
            capture_creator,
            capture_identity,
            originals,
            begins,
            begin_requests,
            content,
            content_bytes,
            realized,
            admitted,
            staged,
            active,
            fenced,
            native_effect_attempted,
            immediate,
            current_operation,
            terminals,
            common_coordinator,
            world_coordinator,
            connected_coordinator,
            complete_coordinator,
            complete_storage,
            complete_capture_profile,
            complete_confirmation_selection,
            complete_ack_emitter_selection,
            complete_restore_selection,
            complete_protocol_metadata_limits,
            complete_protocol_metadata_birth_facts,
            complete_restore_input_emitter_selection,
            complete_capture_allocation_selection,
        } = self;
        observer.observe(restoration_activation_required)?;
        observer.observe(selection)?;
        roots.observe_shared(
            observer,
            crate::retained_metadata::aliases::MetadataSharedKind::NativeControlIdentity,
            capture_identity.as_ref(),
        )?;
        observer.tree::<Id, (HashRef, PacketControlReply)>(originals.len())?;
        for (id, (hash, reply)) in originals {
            let PacketControlReply { body, evidence } = reply;
            observer.observe(id)?;
            observer.observe(hash)?;
            observer.observe(body)?;
            observer.vector::<(ContentRef, Vec<u8>)>(evidence.capacity())?;
            for (reference, bytes) in evidence {
                observer.observe(reference)?;
                // Primitive byte slots have no child heap. This selected
                // Fresh-only requested-storage walk records the actual bank
                // capacity and initialized extent without per-byte visits.
                observer.vector::<u8>(bytes.capacity())?;
                observer.observe(&bytes.len())?;
            }
        }
        observer.observe(begins)?;
        observer.observe(begin_requests)?;
        observer.observe(content)?;
        observer.observe(content_bytes)?;
        observer.observe(capture_creator)?;
        observer.observe(realized)?;
        observer.observe(admitted)?;
        // The lifecycle guard proves these optional payloads absent. Preserve
        // their explicit roots without fabricating a staged/restored value.
        observer.observe(&complete_restored_evidence.is_some())?;
        observer.observe(&complete_restored_hold.is_some())?;
        observer.observe(&staged.is_some())?;
        observer.observe(&active.is_some())?;
        observer.observe(&common_coordinator.is_some())?;
        observer.observe(&world_coordinator.is_some())?;
        observer.observe(&connected_coordinator.is_some())?;
        observer.observe(fenced)?;
        observer.observe(native_effect_attempted)?;
        observer.observe(immediate)?;
        observer.observe(current_operation)?;
        observer.observe(terminals)?;
        observer.observe(complete_coordinator)?;
        observer.observe(complete_storage)?;
        observer.observe(complete_capture_profile)?;
        observer.observe(complete_confirmation_selection)?;
        observer.observe(complete_ack_emitter_selection)?;
        observer.observe(complete_restore_selection)?;
        observer.observe(complete_protocol_metadata_limits)?;
        observer.observe(complete_protocol_metadata_birth_facts)?;
        observer.observe(complete_restore_input_emitter_selection)?;
        observer.observe(complete_capture_allocation_selection)?;
        match program {
            NativeProgram::OutputOnly(program) => {
                program.observe_fresh_restore_metadata(observer)?
            }
            NativeProgram::Connected(program) => {
                program.observe_fresh_restore_metadata(observer)?
            }
            NativeProgram::RestorationInProgress => {
                return Err(ProviderError::Conflict("fresh model census incomplete"));
            }
        }
        if !self.original_fresh_report_window_data()? {
            return Err(ProviderError::Correlation("fresh Control census changed"));
        }
        policy.authenticate_original_control_selection(&self.selection)
    }
}

/// Borrows the actual inactive selection, gate proof and inventory projection.
pub(crate) struct OriginalNativeFreshReportView<'a> {
    control: &'a PacketControl,
    gate: &'a ContentRef,
    inventory: FreshInventory<'a>,
    inventory_fields: crate::retained_metadata::RetainedProtocolMetadataFacts,
}

enum FreshInventory<'a> {
    Producer(super::super::fresh_inventory::OriginalFreshProducerInventory<'a>),
    Reactive(super::super::connected::fresh_inventory::OriginalFreshReactiveInventory<'a>),
}

impl Serialize for FreshInventory<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Producer(view) => view.serialize(serializer),
            Self::Reactive(view) => view.serialize(serializer),
        }
    }
}

impl OriginalNativeFreshReportView<'_> {
    pub(crate) fn selection_data(&self) -> &PacketControlSelection {
        &self.control.selection
    }
    pub(crate) fn gate_receipt_data(&self) -> &ContentRef {
        self.gate
    }
    pub(crate) fn inventory_data(&self) -> impl Serialize + '_ {
        &self.inventory
    }
    pub(crate) fn inventory_fields_data(
        &self,
    ) -> crate::retained_metadata::RetainedProtocolMetadataFacts {
        self.inventory_fields
    }
    /// Counts actual typed Bytes formatter fields, independently of model banks.
    pub(crate) fn inventory_formatter_fields_data(
        &self,
    ) -> Result<crate::retained_metadata::RetainedProtocolMetadataFacts, ProviderError> {
        match &self.inventory {
            FreshInventory::Producer(view) => view.formatter_fields_data(),
            // The actual reactive borrow constructor proves all six serialized
            // inventory arrays empty before lending this immutable view. Its
            // reserved baseline arrays invoke no Bytes formatter here.
            FreshInventory::Reactive(_) => {
                Ok(crate::retained_metadata::MetadataObserver::new().finish())
            }
        }
    }

    pub(crate) fn inventory_domain_data(&self) -> &'static str {
        match &self.inventory {
            FreshInventory::Producer(_) => "source-owned.packet-inventory.v1",
            FreshInventory::Reactive(_) => "source-owned.packet-connected-inventory/4",
        }
    }
}

impl PacketControl {
    pub(crate) fn original_fresh_report_view_counter_scratch_data() -> usize {
        [
            std::mem::size_of::<OriginalNativeFreshReportView<'static>>(),
            std::mem::size_of::<crate::retained_metadata::MetadataObserver>(),
            std::mem::size_of::<crate::retained_metadata::RetainedProtocolMetadataFacts>(),
            std::mem::size_of::<blake3::Hasher>(),
            std::mem::size_of::<blake3::Hash>(),
            std::mem::size_of::<[u8; 64]>(),
            12 * std::mem::size_of::<usize>(),
        ]
        .into_iter()
        .try_fold(0usize, usize::checked_add)
        .unwrap_or(usize::MAX)
    }

    pub(crate) fn borrow_original_fresh_report_data(
        &self,
        policy: &super::super::Native5Policy,
    ) -> Result<OriginalNativeFreshReportView<'_>, ProviderError> {
        if !self.original_fresh_report_window_data()? {
            return Err(fresh_view_refused());
        }
        policy.authenticate_original_control_selection(&self.selection)?;
        let mut gate = None;
        for (_, reply) in self.originals.values() {
            let Some(result) = reply.body.get("result").and_then(Value::as_object) else {
                continue;
            };
            if result.len() != 3
                || !result.contains_key("realization_manifest")
                || result.get("prepared_token").and_then(Value::as_str)
                    != Some(self.selection.prepared_token.as_str())
            {
                continue;
            }
            let actual = result
                .get("closed_gate_receipt")
                .ok_or_else(fresh_view_refused)?;
            let mut proof = None;
            for (reference, bytes) in &reply.evidence {
                if borrowed_reference_matches(actual, reference) {
                    authenticate_gate_bytes(reference, bytes)?;
                    if proof.replace(reference).is_some() {
                        return Err(fresh_view_refused());
                    }
                }
            }
            if gate
                .replace(proof.ok_or_else(fresh_view_refused)?)
                .is_some()
            {
                return Err(fresh_view_refused());
            }
        }
        let mut fields = crate::retained_metadata::MetadataObserver::new();
        let inventory = match &self.program {
            NativeProgram::OutputOnly(program) => {
                FreshInventory::Producer(program.borrow_original_fresh_inventory(&mut fields)?)
            }
            NativeProgram::Connected(program) => {
                FreshInventory::Reactive(program.borrow_original_fresh_inventory(&mut fields)?)
            }
            NativeProgram::RestorationInProgress => return Err(fresh_view_refused()),
        };
        Ok(OriginalNativeFreshReportView {
            control: self,
            gate: gate.ok_or_else(fresh_view_refused)?,
            inventory,
            inventory_fields: fields.finish(),
        })
    }
}

pub(super) fn borrowed_reference_matches(value: &Value, expected: &ContentRef) -> bool {
    let Some(value) = value.as_object().filter(|value| value.len() == 3) else {
        return false;
    };
    let Some(hash) = value
        .get("hash")
        .and_then(Value::as_object)
        .filter(|hash| hash.len() == 3)
    else {
        return false;
    };
    let length = value
        .get("length")
        .and_then(Value::as_str)
        .is_some_and(|text| {
            !text.is_empty()
                && text.len() <= 20
                && (text == "0" || !text.starts_with('0'))
                && text.bytes().all(|byte| byte.is_ascii_digit())
                && text.parse::<u64>() == Ok(expected.length.get())
        });
    length
        && value.get("media_type").and_then(Value::as_str) == Some(expected.media_type.as_str())
        && hash.get("algorithm").and_then(Value::as_str) == Some(expected.hash.algorithm.as_str())
        && hash.get("domain").and_then(Value::as_str) == Some(expected.hash.domain.as_str())
        && hash.get("digest").and_then(Value::as_str) == Some(expected.hash.digest.as_str())
}

fn authenticate_gate_bytes(reference: &ContentRef, bytes: &[u8]) -> Result<(), ProviderError> {
    let domain = "cnp.blob.v1";
    let length = u64::try_from(bytes.len()).map_err(|_| fresh_view_refused())?;
    if reference.hash.algorithm != "blake3-256"
        || reference.hash.domain != domain
        || reference.media_type != "application/json"
        || reference.length.get() != length
    {
        return Err(fresh_view_refused());
    }
    let mut hash = blake3::Hasher::new();
    hash.update(b"CNP/1\0");
    hash.update(&(domain.len() as u32).to_be_bytes());
    hash.update(domain.as_bytes());
    hash.update(&length.to_be_bytes());
    hash.update(bytes);
    if reference.hash.digest != hash.finalize().to_hex().as_str() {
        return Err(fresh_view_refused());
    }
    Ok(())
}

fn fresh_view_refused() -> ProviderError {
    ProviderError::Correlation("fresh actual selection/gate/inventory view differs")
}

// crucible-lint: allow panic-shortcut -- normative full references and causal mismatches are the observations.
#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "actual canonical gate proof and full ContentRef are test observations"
)]
mod tests {
    use super::*;

    #[test]
    fn borrowed_gate_reference_matches_normative_full_hash_and_each_field() {
        let bytes = br#"{"gate_closed":true,"prepared_token":"same-original"}"#;
        let reference =
            crucible_node_format::canonical::content_ref(bytes, "application/json").unwrap();
        let value = serde_json::to_value(&reference).unwrap();
        assert!(borrowed_reference_matches(&value, &reference));
        authenticate_gate_bytes(&reference, bytes).unwrap();

        for path in [
            ["hash", "algorithm"],
            ["hash", "domain"],
            ["hash", "digest"],
        ] {
            let mut changed = value.clone();
            changed[path[0]][path[1]] = Value::String("changed".into());
            assert!(!borrowed_reference_matches(&changed, &reference));
        }
        for key in ["length", "media_type"] {
            let mut changed = value.clone();
            changed[key] = Value::String("changed".into());
            assert!(!borrowed_reference_matches(&changed, &reference));
        }
        let mut changed = value.clone();
        changed
            .as_object_mut()
            .unwrap()
            .insert("extra".into(), Value::Bool(true));
        assert!(!borrowed_reference_matches(&changed, &reference));
        let mut changed = bytes.to_vec();
        changed[0] = b'[';
        assert!(authenticate_gate_bytes(&reference, &changed).is_err());
    }
}
