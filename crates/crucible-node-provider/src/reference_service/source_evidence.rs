//! Keeps selected lineage source roles and pre-effect native evidence credit.
//!
//! Typed identities remain independent even when their exact bytes share a
//! digest. Operational transfer keys do not change public event identities.

use crucible_node_contract::{ContentRef, canonical};

use crate::ProviderError;

const MAXIMUM_OBJECTS: usize = 4096;
const NATIVE_WINDOW_OBJECTS: usize = 72;
const NATIVE_WINDOW_BYTES: usize = 600 * 1024;
const PUBLIC_WINDOW_OBJECTS: usize = 8;
const PUBLIC_WINDOW_BYTES: usize = PUBLIC_WINDOW_OBJECTS * 65_536;

pub(super) struct SourceEvidence {
    objects: Vec<(ContentRef, Vec<u8>)>,
    bytes: usize,
    reserved_native_objects: usize,
    reserved_native_bytes: usize,
    maximum_bytes: usize,
}

impl SourceEvidence {
    pub(super) fn new(maximum_bytes: usize) -> Result<Self, ProviderError> {
        let mut objects = Vec::new();
        objects
            .try_reserve_exact(MAXIMUM_OBJECTS)
            .map_err(|_| ProviderError::ResourceExhausted("lineage source evidence slots"))?;
        Ok(Self {
            objects,
            bytes: 0,
            reserved_native_objects: 0,
            reserved_native_bytes: 0,
            maximum_bytes,
        })
    }

    pub(super) fn preflight_initialization(&self) -> Result<(), ProviderError> {
        let bytes = 2 * (65_536 + 4) + PUBLIC_WINDOW_BYTES;
        let objects = 2 + PUBLIC_WINDOW_OBJECTS;
        if self
            .objects
            .len()
            .checked_add(objects)
            .is_none_or(|count| count > MAXIMUM_OBJECTS)
            || self
                .bytes
                .checked_add(bytes)
                .is_none_or(|count| count > self.maximum_bytes)
        {
            return Err(ProviderError::ResourceExhausted(
                "lineage actual initialization source credit",
            ));
        }
        Ok(())
    }

    pub(super) fn reserve_native_window(&mut self) -> Result<(), ProviderError> {
        let reserved_objects = self
            .reserved_native_objects
            .checked_add(NATIVE_WINDOW_OBJECTS)
            .ok_or(ProviderError::ResourceExhausted(
                "lineage native object credit",
            ))?;
        let reserved_bytes = self
            .reserved_native_bytes
            .checked_add(NATIVE_WINDOW_BYTES)
            .ok_or(ProviderError::ResourceExhausted(
                "lineage native byte credit",
            ))?;
        if self
            .objects
            .len()
            .checked_add(reserved_objects)
            .and_then(|count| count.checked_add(PUBLIC_WINDOW_OBJECTS))
            .is_none_or(|count| count > MAXIMUM_OBJECTS)
            || self
                .bytes
                .checked_add(reserved_bytes)
                .and_then(|bytes| bytes.checked_add(PUBLIC_WINDOW_BYTES))
                .is_none_or(|bytes| bytes > self.maximum_bytes)
        {
            return Err(ProviderError::ResourceExhausted(
                "lineage complete source window credit",
            ));
        }
        // These reservations stay owned even after public ACK or a failed
        // native command: historical native relation bodies remain retained.
        self.reserved_native_objects = reserved_objects;
        self.reserved_native_bytes = reserved_bytes;
        Ok(())
    }

    pub(super) fn content(&self, reference: &ContentRef) -> Option<&[u8]> {
        self.objects
            .iter()
            .find(|(original, _)| original == reference)
            .map(|(_, bytes)| bytes.as_slice())
    }

    pub(super) fn store(
        &mut self,
        reference: ContentRef,
        bytes: Vec<u8>,
    ) -> Result<ContentRef, ProviderError> {
        reference.verify(&bytes)?;
        for (original, original_bytes) in &self.objects {
            if original.hash == reference.hash && original_bytes != &bytes {
                return Err(ProviderError::Conflict(
                    "lineage digest has conflicting original bytes",
                ));
            }
            if original == &reference {
                return Ok(reference);
            }
        }
        let total = self
            .bytes
            .checked_add(bytes.len())
            .ok_or(ProviderError::ResourceExhausted(
                "lineage source byte arithmetic",
            ))?;
        if self
            .objects
            .len()
            .checked_add(self.reserved_native_objects)
            .is_none_or(|count| count >= MAXIMUM_OBJECTS)
            || total
                .checked_add(self.reserved_native_bytes)
                .is_none_or(|bytes| bytes > self.maximum_bytes)
        {
            return Err(ProviderError::ResourceExhausted(
                "lineage source content custody",
            ));
        }
        self.objects.push((reference.clone(), bytes));
        self.bytes = total;
        Ok(reference)
    }
}

pub(super) fn typed_key(reference: &ContentRef) -> Result<String, ProviderError> {
    let value =
        serde_json::to_value(reference).map_err(crucible_node_contract::ContractError::from)?;
    Ok(canonical::hash(
        "cnp.reference.lineage-transfer-role.v1",
        &canonical::canonical_json(&value)?,
    )?
    .digest)
}

#[cfg(test)]
#[path = "source_evidence_tests.rs"]
mod tests;
