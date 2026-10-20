//! Encodes exact consumed control pins, policy occurrences and source records.
//!
//! ```text
//! required-control-pin = [kind, owner_registration, relative_key, raw_digest32]
//! consumed-root-policy = [root_digest32, absolute_path, [[props, overrides]+]]
//! ```

use super::*;

impl Record for RequiredControlPin {
    fn read(decoder: &mut Decoder<'_>) -> Result<Self, EvidenceError> {
        array(decoder, 4)?;
        let kind = match decoder.uint()? {
            0 => ControlKind::Registration,
            1 => ControlKind::Bootstrap,
            2 => ControlKind::Association,
            3 => ControlKind::Import,
            4 => ControlKind::ImportBinding,
            5 => ControlKind::ImportTrust,
            _ => return Err(EvidenceError::Schema),
        };

        Ok(Self {
            kind,
            owner: read(decoder)?,
            key: text(decoder)?,
            digest: digest(decoder)?,
        })
    }

    fn write(&self, output: &mut Vec<u8>) -> Result<(), EvidenceError> {
        write_array(output, 4);
        write_uint(
            output,
            match self.kind {
                ControlKind::Registration => 0,
                ControlKind::Bootstrap => 1,
                ControlKind::Association => 2,
                ControlKind::Import => 3,
                ControlKind::ImportBinding => 4,
                ControlKind::ImportTrust => 5,
            },
        );

        self.owner.write(output)?;
        write_text(output, &self.key);
        write_bytes(output, &self.digest);
        Ok(())
    }
}

impl Record for ConsumedRootPolicy {
    fn read(decoder: &mut Decoder<'_>) -> Result<Self, EvidenceError> {
        array(decoder, 3)?;
        let root = digest(decoder)?;
        let path = decoder.bytes(4097)?.to_vec();

        let count = decoder.array(crate::tree_format::MAX_GRAFT_DEPTH + 1)?;
        let mut layers = Vec::new();
        for _ in 0..count {
            array(decoder, 2)?;
            let properties = decoder
                .bytes(crate::tree_format::MAX_NODE_ITEMS_BYTES)?
                .to_vec();
            let overrides = decoder
                .bytes(crate::tree_format::MAX_NODE_ITEMS_BYTES)?
                .to_vec();
            layers.push(ConsumedRootLayer {
                properties,
                overrides,
            });
        }
        Ok(Self { root, path, layers })
    }

    fn write(&self, output: &mut Vec<u8>) -> Result<(), EvidenceError> {
        write_array(output, 3);
        write_bytes(output, &self.root);
        write_bytes(output, &self.path);

        write_array(output, self.layers.len());
        for layer in &self.layers {
            write_array(output, 2);
            write_bytes(output, &layer.properties);
            write_bytes(output, &layer.overrides);
        }

        Ok(())
    }
}

impl Record for ConsumedViewPolicy {
    fn read(decoder: &mut Decoder<'_>) -> Result<Self, EvidenceError> {
        array(decoder, 3)?;

        Ok(Self {
            view: digest(decoder)?,
            default_domain: text(decoder)?,
            roots: read_rows(decoder)?,
        })
    }

    fn write(&self, output: &mut Vec<u8>) -> Result<(), EvidenceError> {
        write_array(output, 3);
        write_bytes(output, &self.view);
        write_text(output, &self.default_domain);
        write_rows(output, &self.roots)
    }
}

impl Record for ConsumedViewInterpretation {
    fn read(decoder: &mut Decoder<'_>) -> Result<Self, EvidenceError> {
        array(decoder, 4)?;
        let view = digest(decoder)?;
        let original_root = digest(decoder)?;
        let mode = match decoder.uint()? {
            0 => ViewInterpretationMode::Legacy,
            1 => ViewInterpretationMode::Recorded,
            _ => return Err(EvidenceError::Schema),
        };

        // Unsupported non-property semantic uints remain ordinary context data.
        // Property revisions still require a spec-registered vocabulary.
        // Existing validated registry decoders, including global key 4, retain
        // their supported-interpretation checks unchanged.
        let registries = <ConfiguredRegistryInputs as Record>::read(decoder)?;
        Ok(Self {
            view,
            original_root,
            mode,
            registries,
        })
    }

    fn write(&self, output: &mut Vec<u8>) -> Result<(), EvidenceError> {
        write_array(output, 4);
        write_bytes(output, &self.view);
        write_bytes(output, &self.original_root);
        write_uint(
            output,
            match self.mode {
                ViewInterpretationMode::Legacy => 0,
                ViewInterpretationMode::Recorded => 1,
            },
        );
        self.registries.write(output)
    }
}

impl ConsumedViewInterpretation {
    /// Encodes a canonical ordinary per-view interpretation record.
    ///
    /// Spec-registered property vocabularies are required. Unsupported
    /// non-property semantic uints are preserved as ordinary data.
    /// This creates no original, current or producer authority.
    ///
    /// # Errors
    /// Rejects unregistered property revisions, malformed or contradictory name
    /// fences, and vocabulary disagreements decidable from represented data.
    pub fn encode(&self) -> Result<Vec<u8>, EvidenceError> {
        self.validate()?;
        let mut output = Vec::new();
        self.write(&mut output)?;
        Ok(output)
    }

    /// Decodes canonical bytes as ordinary per-view interpretation data.
    ///
    /// Supported semantics and independently selected input association are
    /// separate checks. Unregistered property revisions reject; other unsupported
    /// semantic uint values supply no behavior when parsed as ordinary data.
    ///
    /// # Errors
    /// Rejects noncanonical or truncated input, unknown modes, invalid field
    /// shapes, unregistered property revisions, contradictory name fences and
    /// trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, EvidenceError> {
        let mut decoder = Decoder::new(bytes);
        let record = read::<Self>(&mut decoder)?;
        decoder.finish()?;
        Ok(record)
    }
}

impl Record for LineageUsedInputs {
    fn read(decoder: &mut Decoder<'_>) -> Result<Self, EvidenceError> {
        let count = decoder.map(8)?;
        if count != 7 && count != 8 {
            return Err(EvidenceError::Schema);
        }
        key(decoder, 0)?;
        version(decoder, 1)?;

        key(decoder, 1)?;
        let issuers = read_rows(decoder)?;
        key(decoder, 2)?;
        let disclosures = read_rows(decoder)?;
        key(decoder, 3)?;
        let controls = read_rows(decoder)?;

        key(decoder, 4)?;
        let registries = read(decoder)?;
        key(decoder, 5)?;
        let configuration = read(decoder)?;
        key(decoder, 6)?;
        let views = read_rows(decoder)?;
        let view_interpretations = if count == 8 {
            key(decoder, 7)?;
            Some(read_rows(decoder)?)
        } else {
            None
        };
        Ok(Self {
            issuers,
            disclosures,
            controls,
            registries,
            configuration,
            views,
            view_interpretations,
        })
    }

    fn write(&self, output: &mut Vec<u8>) -> Result<(), EvidenceError> {
        header(output, 7 + usize::from(self.view_interpretations.is_some()));

        write_uint(output, 1);
        write_rows(output, &self.issuers)?;
        write_uint(output, 2);
        write_rows(output, &self.disclosures)?;
        write_uint(output, 3);
        write_rows(output, &self.controls)?;

        write_uint(output, 4);
        self.registries.write(output)?;
        write_uint(output, 5);
        self.configuration.write(output)?;
        write_uint(output, 6);
        write_rows(output, &self.views)?;
        if let Some(contexts) = &self.view_interpretations {
            write_uint(output, 7);
            write_rows(output, contexts)?;
        }

        Ok(())
    }
}

impl Record for CheckedLineage {
    fn read(decoder: &mut Decoder<'_>) -> Result<Self, EvidenceError> {
        map(decoder, 10)?;

        key(decoder, 1)?;
        let source_name = text(decoder)?;
        key(decoder, 2)?;
        let source = RefRecord::decode(decoder.bytes(decoder.remaining().len())?)?;
        key(decoder, 3)?;
        let commit_id = digest(decoder)?;
        key(decoder, 4)?;
        let commit_bytes = bytes(decoder)?;

        key(decoder, 5)?;
        let guard_digest = digest(decoder)?;
        key(decoder, 6)?;
        let loss_generation = decoder.uint()?;
        key(decoder, 7)?;
        let controls = read_rows(decoder)?;
        key(decoder, 8)?;
        let original = read(decoder)?;
        key(decoder, 9)?;
        let used = read(decoder)?;

        Ok(Self {
            source_name,
            source,
            commit_id,
            commit_bytes,
            guard_digest,
            loss_generation,
            controls,
            original,
            used,
        })
    }

    fn write(&self, output: &mut Vec<u8>) -> Result<(), EvidenceError> {
        header(output, 10);

        write_uint(output, 1);
        write_text(output, &self.source_name);
        write_uint(output, 2);
        write_bytes(output, &self.source.encode()?);
        write_uint(output, 3);
        write_bytes(output, &self.commit_id);
        write_uint(output, 4);
        write_bytes(output, &self.commit_bytes);

        write_uint(output, 5);
        write_bytes(output, &self.guard_digest);
        write_uint(output, 6);
        write_uint(output, self.loss_generation);
        write_uint(output, 7);
        write_rows(output, &self.controls)?;
        write_uint(output, 8);
        self.original.write(output)?;
        write_uint(output, 9);
        self.used.write(output)
    }
}
