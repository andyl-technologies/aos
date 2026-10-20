//! Checks exact control selectors, absolute policy occurrences and commit IDs.

use super::policy::{property_map, property_map_structure, registry_structure};
use super::*;
use crate::refs::{Commit, RefClass};

fn decimal(value: &str) -> Result<(), EvidenceError> {
    if value.is_empty()
        || value.len() > 1 && value.starts_with('0')
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(EvidenceError::Schema);
    }
    value.parse::<u64>().map_err(|_| EvidenceError::Schema)?;
    Ok(())
}

fn digest_key(key: &str, prefix: &str) -> Result<(), EvidenceError> {
    let digest = key
        .strip_prefix(prefix)
        .and_then(|key| key.strip_suffix(".cbor"))
        .ok_or(EvidenceError::Schema)?;
    hex(digest)
}

impl Validate for RequiredControlPin {
    fn validate(&self) -> Result<(), EvidenceError> {
        self.owner.validate()?;
        match self.kind {
            ControlKind::Registration if self.key == "registration.cbor" => Ok(()),
            ControlKind::Registration => Err(EvidenceError::Schema),
            ControlKind::Bootstrap => {
                let key = self
                    .key
                    .strip_prefix("bootstrap-")
                    .and_then(|key| key.strip_suffix(".cbor"))
                    .ok_or(EvidenceError::Schema)?;
                let mut parts = key.split('-');
                let original = parts.next().ok_or(EvidenceError::Schema)?;
                hex(original)?;
                hex(parts.next().ok_or(EvidenceError::Schema)?)?;
                decimal(parts.next().ok_or(EvidenceError::Schema)?)?;
                if parts.next().is_some() {
                    return Err(EvidenceError::Schema);
                }
                if original != digest_text(*self.owner.original_id()) {
                    return Err(EvidenceError::Contradiction);
                }
                Ok(())
            }
            ControlKind::Association => digest_key(&self.key, "commit-"),
            ControlKind::Import => digest_key(&self.key, "import-"),
            ControlKind::ImportBinding => digest_key(&self.key, "import-binding-"),
            ControlKind::ImportTrust => digest_key(&self.key, "import-trust-"),
        }
    }
}

fn controls(pins: &[RequiredControlPin]) -> Result<(), EvidenceError> {
    let mut previous: Option<(ControlKind, Vec<u8>, &str)> = None;
    for pin in pins {
        pin.validate()?;
        let owner = pin.owner.encode()?;
        let current = (pin.kind, owner, pin.key.as_str());
        if previous.as_ref().is_some_and(|prior| prior >= &current) {
            return Err(EvidenceError::Schema);
        }
        previous = Some(current);
    }
    // An empty pin array is valid format data, never exhaustive verification.
    Ok(())
}

impl RequiredControlPin {
    /// Checks exact record bytes and registered selector associations for this pin.
    ///
    /// This verifies data relationships only; the owner's genuine protected
    /// retention and this pin's necessity remain independent obligations.
    ///
    /// # Errors
    /// Rejects malformed records or inconsistent key, owner, and raw digest.
    pub fn check_record(&self, bytes: &[u8]) -> Result<(), EvidenceError> {
        self.validate()?;
        if blake3::hash(bytes).as_bytes() != &self.digest {
            return Err(EvidenceError::Contradiction);
        }

        let expected_key = match self.kind {
            ControlKind::Registration => {
                if PhysicalRegistration::decode(bytes)? != self.owner {
                    return Err(EvidenceError::Contradiction);
                }
                "registration.cbor".into()
            }
            ControlKind::Bootstrap => {
                let record = OriginalBootstrap::decode(bytes)?;
                if &record.original_id != self.owner.original_id() {
                    return Err(EvidenceError::Contradiction);
                }
                alloc::format!(
                    "bootstrap-{}-{}-{}.cbor",
                    digest_text(record.original_id),
                    blake3::hash(record.ref_name.as_bytes()).to_hex(),
                    record.epoch
                )
            }
            ControlKind::Association => {
                let record = OriginalAssociation::decode(bytes)?;
                if &record.original_id != self.owner.original_id() {
                    return Err(EvidenceError::Contradiction);
                }
                alloc::format!("commit-{}.cbor", digest_text(record.commit))
            }
            ControlKind::Import => {
                let record = OriginalImport::decode(bytes)?;
                alloc::format!("import-{}.cbor", digest_text(record.association.commit))
            }
            ControlKind::ImportBinding => {
                let record = OriginalImportBinding::decode(bytes)?;
                if &record.destination != self.owner.original_id() {
                    return Err(EvidenceError::Contradiction);
                }
                alloc::format!("import-binding-{}.cbor", digest_text(record.commit))
            }
            ControlKind::ImportTrust => {
                let record = OriginalImportTrust::decode(bytes)?;
                if &record.destination != self.owner.original_id() {
                    return Err(EvidenceError::Contradiction);
                }
                alloc::format!("import-trust-{}.cbor", digest_text(record.import_digest))
            }
        };
        if self.key != expected_key {
            return Err(EvidenceError::Contradiction);
        }

        Ok(())
    }
}

impl Validate for ConsumedRootPolicy {
    fn validate(&self) -> Result<(), EvidenceError> {
        if self.path.len() > 4097 || self.path.first() != Some(&b'/') {
            return Err(EvidenceError::Schema);
        }
        if self.path.len() > 1 {
            crate::tree_format::validate_key(&self.path[1..])?;
        }
        if self.layers.is_empty() || self.layers.len() > crate::tree_format::MAX_GRAFT_DEPTH + 1 {
            return Err(EvidenceError::Schema);
        }

        for layer in &self.layers {
            property_map(&layer.properties, None)?;
            property_map(&layer.overrides, None)?;
        }

        Ok(())
    }
}

impl Validate for ConsumedViewPolicy {
    fn validate(&self) -> Result<(), EvidenceError> {
        domain(&self.default_domain)?;
        let mut occurrences = alloc::collections::BTreeMap::new();
        for root in &self.roots {
            root.validate()?;
            if occurrences
                .insert(root.path.as_slice(), root)
                .is_some_and(|prior| prior != root)
            {
                return Err(EvidenceError::Contradiction);
            }
        }

        Ok(())
    }
}

impl Validate for ConsumedViewInterpretation {
    fn validate(&self) -> Result<(), EvidenceError> {
        registry_structure(&self.registries)
    }
}

fn view_contexts(
    inputs: &LineageUsedInputs,
    contexts: &[ConsumedViewInterpretation],
) -> Result<(), EvidenceError> {
    if contexts.windows(2).any(|pair| pair[0].view >= pair[1].view) {
        return Err(EvidenceError::Schema);
    }

    let views: alloc::collections::BTreeSet<_> =
        inputs.views.iter().map(|view| view.view).collect();
    if views.len() != contexts.len() {
        return Err(EvidenceError::Contradiction);
    }
    for context in contexts {
        context.validate()?;
        if !views.contains(&context.view) {
            return Err(EvidenceError::Contradiction);
        }
    }

    // The existing view-policy array keeps its order and representation. Every
    // row for a used view applies that view's one explicit interpretation.
    for view in &inputs.views {
        let index = contexts
            .binary_search_by_key(&view.view, |context| context.view)
            .map_err(|_| EvidenceError::Contradiction)?;
        let context = &contexts[index];
        let original = view
            .roots
            .iter()
            .find(|root| root.path == b"/")
            .ok_or(EvidenceError::Contradiction)?;
        if original.root != context.original_root {
            return Err(EvidenceError::Contradiction);
        }

        for root in &view.roots {
            for layer in &root.layers {
                property_map_structure(&layer.properties, &context.registries)?;
                property_map_structure(&layer.overrides, &context.registries)?;
            }
        }
    }

    // Association with actual signed Commit.tree and genuinely selected mode
    // remains an independent caller check, never a claim-decoder capability.
    Ok(())
}

impl Validate for LineageUsedInputs {
    fn validate(&self) -> Result<(), EvidenceError> {
        issuers(&self.issuers)?;
        disclosures(&self.disclosures)?;
        controls(&self.controls)?;
        self.registries.validate()?;
        self.configuration.validate()?;

        if let Some(contexts) = &self.view_interpretations {
            for view in &self.views {
                view.validate()?;
            }
            view_contexts(self, contexts)?;
        } else {
            // Preserve the legacy global fence and absent-key validation exactly.
            for view in &self.views {
                view.validate()?;
                for root in &view.roots {
                    for layer in &root.layers {
                        property_map(&layer.properties, Some(&self.registries))?;
                        property_map(&layer.overrides, Some(&self.registries))?;
                    }
                }
            }
        }

        // Authentic signed trees and independent defaults, ordering and
        // completeness of actually used inputs cannot be inferred from bytes.
        Ok(())
    }
}

impl LineageUsedInputs {
    /// Reports whether complete supported per-view interpretation data is present.
    ///
    /// Absence returns false without inferring a Legacy selection. A true result
    /// describes ordinary data only; it authenticates no signed source or producer
    /// and grants no original/current authority, index relationship or cold/carry
    /// permission. An empty used set supplies no nonempty signed-source evidence.
    ///
    /// # Errors
    /// Rejects malformed or contradictory inputs, unsupported per-view semantic
    /// profiles, and property values violating their supported per-view fence.
    pub fn check_supported_view_contexts(&self) -> Result<bool, EvidenceError> {
        self.validate()?;
        let Some(contexts) = &self.view_interpretations else {
            return Ok(false);
        };
        for context in contexts {
            context.check_supported_interpretation()?;
        }

        for view in &self.views {
            let index = contexts
                .binary_search_by_key(&view.view, |context| context.view)
                .map_err(|_| EvidenceError::Contradiction)?;
            let registries = &contexts[index].registries;
            for root in &view.roots {
                for layer in &root.layers {
                    property_map(&layer.properties, Some(registries))?;
                    property_map(&layer.overrides, Some(registries))?;
                }
            }
        }

        Ok(true)
    }
}

impl Validate for CheckedLineage {
    fn validate(&self) -> Result<(), EvidenceError> {
        let name = RefName::parse(&self.source_name).map_err(|_| EvidenceError::Schema)?;
        if name.class() == RefClass::Notes {
            return Err(EvidenceError::Schema);
        }
        self.source.encode()?;
        self.original.validate()?;
        controls(&self.controls)?;
        self.used.validate()?;

        if self.controls != self.used.controls {
            return Err(EvidenceError::Contradiction);
        }
        let commit = Commit::decode(&self.commit_bytes)?;
        if commit.signature.is_none()
            || commit.identity()? != self.commit_id
            || self.source.commit != self.commit_id
        {
            return Err(EvidenceError::Contradiction);
        }

        // Source refs may be tags or aliases. Historical authoring names and
        // current serving names are not equated by an evidence decoder.
        Ok(())
    }
}

impl CheckedLineage {
    /// Checks an exact named Guard snapshot's raw digest and interpretation inputs.
    ///
    /// Foreign originals and consumed view defaults remain independent of the
    /// current Guard's physical registration. This creates no Guard authority.
    ///
    /// # Errors
    /// Rejects malformed Guard snapshots or mismatched raw digest, configuration,
    /// and registered interpretation inputs.
    pub fn check_guard_snapshot(&self, bytes: &[u8]) -> Result<(), EvidenceError> {
        let snapshot = GuardSnapshot::decode(bytes)?;
        if blake3::hash(bytes).as_bytes() != &self.guard_digest
            || snapshot.configuration != self.used.configuration
            || snapshot.registries != self.used.registries
        {
            return Err(EvidenceError::Contradiction);
        }

        Ok(())
    }
}
