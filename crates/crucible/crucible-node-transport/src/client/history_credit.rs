//! Counts complete borrowed history shapes before owning archival copies.

use std::io::{self, Write};

use serde::{
    Serialize, Serializer,
    ser::{SerializeSeq, SerializeStruct},
};

pub(super) struct Sequence<F>(pub(super) F);

impl<F, I> Serialize for Sequence<F>
where
    F: Fn() -> I,
    I: Iterator,
    I::Item: Serialize,
{
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(None)?;
        for item in (self.0)() {
            sequence.serialize_element(&item)?;
        }
        sequence.end()
    }
}

// A maximal decimal byte array bounds both the actual JSON byte arrays and
// unpadded base64 strings, including the empty representation, without encoding
// or copying any original private bytes during credit admission.
pub(crate) struct ByteCredit(pub(crate) usize);

impl Serialize for ByteCredit {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0))?;
        for _ in 0..self.0 {
            sequence.serialize_element(&255u8)?;
        }
        sequence.end()
    }
}

pub(crate) struct Count {
    maximum: usize,
    used: usize,
}

impl Count {
    pub(crate) fn new(maximum: usize) -> Self {
        Self { maximum, used: 0 }
    }

    pub(crate) fn used(&self) -> usize {
        self.used
    }
}

impl Write for Count {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.used = self
            .used
            .checked_add(bytes.len())
            .filter(|used| *used <= self.maximum)
            .ok_or_else(|| io::Error::other("complete original history exceeds selected credit"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) struct BootstrapCredit<'a>(
    pub(super) &'a crate::reference_service::ReferenceServiceBootstrap,
);

#[derive(Serialize)]
struct InstalledCredit<'a> {
    reference: &'a crucible_node_format::ContentRef,
    bytes: ByteCredit,
}

impl Serialize for BootstrapCredit<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let original = self.0;
        let mut body = serializer.serialize_struct("ReferenceServiceBootstrap", 18)?;
        body.serialize_field("authority", &original.authority)?;
        body.serialize_field("node_id", &original.node_id)?;
        body.serialize_field("owner_id", &original.owner_id)?;
        body.serialize_field("controller_uid", &original.controller_uid)?;
        body.serialize_field("quantum_ps", &original.quantum_ps)?;
        body.serialize_field("host_budget_ns", &original.host_budget_ns)?;
        body.serialize_field("limits", &original.limits)?;
        body.serialize_field("resource_limits", &original.resource_limits)?;
        body.serialize_field("world_binding_hash", &original.world_binding_hash)?;
        body.serialize_field("admission_receipt", &original.admission_receipt)?;
        body.serialize_field("admission_id", &original.admission_id)?;
        body.serialize_field("prepared_token", &original.prepared_token)?;
        body.serialize_field("gate_id", &original.gate_id)?;
        body.serialize_field("transaction_id", &original.transaction_id)?;
        body.serialize_field("activation_id", &original.activation_id)?;
        body.serialize_field("world_generation", &original.world_generation)?;
        body.serialize_field(
            "admission_token",
            &ByteCredit(original.admission_token.as_slice().len()),
        )?;
        body.serialize_field(
            "installed_content",
            &Sequence(|| {
                original
                    .installed_content
                    .iter()
                    .map(|content| InstalledCredit {
                        reference: &content.reference,
                        bytes: ByteCredit(content.bytes.as_slice().len()),
                    })
            }),
        )?;
        body.end()
    }
}
