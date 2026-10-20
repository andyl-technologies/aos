//! Encodes whole current collection and copied placement fence records.
//!
//! ```text
//! CurrentCollectionFence = {0: 1, 1: capabilities, ..., 9: control-pins}
//! CopiedPlacementFence = {0: 2, 1: capabilities, ..., 10: genesis, 11: projection}
//! ```

use super::*;
use crate::gc::publication::CommittedSelection;
use crate::gc::publication::evidence::RequiredControlPin;
use crate::refs::RefLogRecord;

fn refs(decoder: &mut Decoder<'_>) -> Result<Vec<FenceRef>, RetirementError> {
    let count = decoder.array(decoder.remaining().len())?;
    // A declared count is untrusted. Allocate only after a complete row validates;
    // padding after an invalid first row must not reserve a large typed array.
    let mut refs = Vec::new();
    for _ in 0..count {
        array(decoder, 4)?;
        let name = text(decoder)?;
        if refs
            .last()
            .is_some_and(|previous: &FenceRef| previous.name.as_bytes() >= name.as_bytes())
        {
            return Err(RetirementError::Schema);
        }
        let current = optional(decoder, |decoder| blob(decoder, MAX_RECORD_BYTES))?;
        let selection = embedded(decoder, |bytes| Ok(CommittedSelection::decode(bytes)?))?;
        let log = optional(decoder, |decoder| {
            embedded(decoder, |bytes| {
                RefLogRecord::decode(bytes)
                    .map_err(|error| RetirementError::Publication(PublicationError::Ref(error)))
            })
        })?;
        let row = FenceRef {
            name,
            current,
            selection,
            log,
        };
        validation::fence::ref_row(&row)?;
        refs.push(row);
    }
    Ok(refs)
}

fn prefix(decoder: &mut Decoder<'_>) -> Result<CurrentCollectionFence, RetirementError> {
    key(decoder, 1)?;
    let capabilities = blob(decoder, MAX_RECORD_BYTES)?;
    key(decoder, 2)?;
    let manifest = optional(decoder, |decoder| blob(decoder, MAX_RECORD_BYTES))?;
    key(decoder, 3)?;
    let refs = refs(decoder)?;
    key(decoder, 4)?;
    let guard = digest(decoder)?;
    key(decoder, 5)?;
    let state = PublicationState::decode(decoder.bytes(MAX_RECORD_BYTES)?)?;
    key(decoder, 6)?;
    let roots = pointer(decoder)?;
    key(decoder, 7)?;
    let marks = pointer(decoder)?;
    key(decoder, 8)?;
    let backend = backend(decoder)?;
    key(decoder, 9)?;
    let count = decoder.array(decoder.remaining().len())?;
    let mut controls = Vec::new();
    for _ in 0..count {
        controls.push(embedded(decoder, |bytes| {
            Ok(RequiredControlPin::decode(bytes)?)
        })?);
    }
    Ok(CurrentCollectionFence {
        capabilities,
        manifest,
        refs,
        guard,
        state,
        roots,
        marks,
        backend,
        controls,
    })
}

fn write_prefix(
    value: &CurrentCollectionFence,
    output: &mut Vec<u8>,
) -> Result<(), RetirementError> {
    write_uint(output, 1);
    write_bytes(output, &value.capabilities);
    write_uint(output, 2);
    write_optional(output, value.manifest.as_ref(), |bytes, output| {
        write_bytes(output, bytes);
        Ok(())
    })?;
    write_uint(output, 3);
    write_array(output, value.refs.len());
    for row in &value.refs {
        write_array(output, 4);
        write_text(output, &row.name);
        write_optional(output, row.current.as_ref(), |bytes, output| {
            write_bytes(output, bytes);
            Ok(())
        })?;
        output.extend(row.selection.encode()?);
        write_optional(output, row.log.as_ref(), |record, output| {
            output.extend(
                record
                    .encode()
                    .map_err(|error| RetirementError::Publication(PublicationError::Ref(error)))?,
            );
            Ok(())
        })?;
    }
    write_uint(output, 4);
    write_bytes(output, &value.guard);
    write_uint(output, 5);
    write_bytes(output, &value.state.encode()?);
    write_uint(output, 6);
    write_pointer(&value.roots, output)?;
    write_uint(output, 7);
    write_pointer(&value.marks, output)?;
    write_uint(output, 8);
    output.extend(value.backend.encode()?);
    write_uint(output, 9);
    write_array(output, value.controls.len());
    for pin in &value.controls {
        output.extend(pin.encode()?);
    }
    Ok(())
}

impl Record for CurrentCollectionFence {
    fn read(decoder: &mut Decoder<'_>) -> Result<Self, RetirementError> {
        if decoder.map(10)? != 10 {
            return Err(RetirementError::Schema);
        }
        version(decoder, 1)?;
        let value = prefix(decoder)?;
        validation::fence::current(&value)?;
        Ok(value)
    }

    fn write(&self, output: &mut Vec<u8>) -> Result<(), RetirementError> {
        validation::fence::current(self)?;
        write_map(output, 10);
        field(output, 0, 1);
        write_prefix(self, output)
    }
}

impl Record for CopiedPlacementFence {
    fn read(decoder: &mut Decoder<'_>) -> Result<Self, RetirementError> {
        if decoder.map(12)? != 12 {
            return Err(RetirementError::Schema);
        }
        version(decoder, 2)?;
        let prefix = prefix(decoder)?;
        key(decoder, 10)?;
        let genesis = slot(decoder)?;
        key(decoder, 11)?;
        let projection = pointer(decoder)?;
        let value = Self {
            capabilities: prefix.capabilities,
            manifest: prefix.manifest.ok_or(RetirementError::Schema)?,
            refs: prefix.refs,
            guard: prefix.guard,
            state: prefix.state,
            roots: prefix.roots,
            marks: prefix.marks,
            backend: prefix.backend,
            controls: prefix.controls,
            genesis,
            projection,
        };
        validation::fence::copied(&value)?;
        Ok(value)
    }

    fn write(&self, output: &mut Vec<u8>) -> Result<(), RetirementError> {
        validation::fence::copied(self)?;
        header(output, 12);
        write_prefix(&self.current_fields(), output)?;
        write_uint(output, 10);
        write_slot(&self.genesis, output)?;
        write_uint(output, 11);
        write_pointer(&self.projection, output)
    }
}
