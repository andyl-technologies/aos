//! Checks record18 syntax and exact seven-bank correspondence without live adoption.

use super::*;

impl PacketNativeImport18RecordPairData {
    fn validate_data(&self) -> Result<(), ProviderError> {
        json_reference(&self.original)?;
        json_reference(&self.terminal)?;
        if self.original == self.terminal {
            return Err(invalid());
        }
        Ok(())
    }
}

impl PacketNativeImport18RecordScopeData {
    fn validate_data(&self) -> Result<(), ProviderError> {
        let target = &self.target;
        if target.native_pid.get() == 0
            || target.native_pid.get() > i32::MAX as u64
            || target.owner_generation.get() == 0
            || target.generation.get() == 0
        {
            return Err(invalid());
        }
        for id in [
            &target.session,
            &target.incarnation,
            &target.node,
            &target.owner,
            &target.activation,
            &target.prepared_token,
            &target.gate,
            &target.admission,
            &target.transaction,
        ] {
            id.validate()?;
        }
        target.binding_hash.validate()?;
        target.world.validate()?;
        json_reference(&self.source_birth)?;
        json_reference(&self.import_binding)?;
        digest32(&self.recipe_identity)?;
        self.bootstrap.validate_data()?;
        self.prepare.validate_data()?;
        for reference in &self.inputs {
            reference.validate()?;
            if reference.length.get() == 0 {
                return Err(invalid());
            }
        }
        Ok(())
    }

    /// Compares every full input reference with its independently supplied role.
    ///
    /// The actual Source/native owners separately authenticate the Prepare,
    /// binding body/reference, recipe, token, completed phases and target. This
    /// checks their supplied DATA roster only and creates no input lease.
    ///
    /// # Errors
    /// Refuses invalid scope, Prepare or binding DATA, or any changed input.
    pub fn authenticate_input_roster_data(
        &self,
        prepare: &PacketCompleteRestorePrepareRequest,
        binding: &PacketNativeImport18Binding,
    ) -> Result<(), ProviderError> {
        self.validate_data()?;
        prepare.validate_data()?;
        binding.validate_data()?;
        for role in PacketNativeImport18InputRole::ALL {
            if &self.inputs[role.ordinal_data()] != role.reference_data(prepare, binding) {
                return Err(invalid());
            }
        }
        Ok(())
    }
}

impl PacketNativeImport18RestoredRecordData {
    /// Checks the exact selected kind, target, full references and physical report.
    ///
    /// The independent maximum restricts this complete serialized body. The caller
    /// admits validation and serializer controls before this walk; this method
    /// neither parses raw bytes nor allocates a canonical body. Matching DATA
    /// issues no model, physical gate, phase credit or accepted Source witness.
    ///
    /// # Errors
    /// Refuses another edition, invalid scope/reference/digest/position, a
    /// kind-inconsistent physical report or a body beyond the supplied maximum.
    pub fn validate_data(&self, maximum: usize) -> Result<(), ProviderError> {
        match self {
            Self::CommitHeld(record) => {
                if record.schema != NATIVE_IMPORT18_RESTORED_RECORD_SCHEMA
                    || !record.physical_gate_held
                {
                    return Err(invalid());
                }
                record.scope.validate_data()?;
                json_reference(&record.commit)?;
                digest32(&record.context_digest)?;
                record.local_cursor.validate()?;
                record.inventory_hash.validate()?;
            }
            Self::FirstObserved(record) => {
                if record.schema != NATIVE_IMPORT18_RESTORED_RECORD_SCHEMA
                    || record.physical_gate_held
                {
                    return Err(invalid());
                }
                record.scope.validate_data()?;
                record.commit.validate_data()?;
                record.arm.validate_data()?;
                record.world.validate_data()?;
                json_reference(&record.observe)?;
                json_reference(&record.native_record)?;
            }
        }
        crate::connection::serialized_credit(self, maximum)?;
        Ok(())
    }
}

fn json_reference(reference: &ContentRef) -> Result<(), ProviderError> {
    reference.validate()?;
    if reference.length.get() == 0 || reference.media_type != "application/json" {
        return Err(invalid());
    }
    Ok(())
}
