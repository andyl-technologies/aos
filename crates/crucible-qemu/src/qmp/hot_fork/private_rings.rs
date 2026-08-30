//! QEMU-owned retention of one branch-private shared-ring descriptor.

use serde_json::Value;

use crate::qmp::{QmpCommandKind, QmpDescriptorName, QmpError};

/// QMP command that retains or releases one authenticated private-ring descriptor.
pub const QMP_HOT_FORK_PRIVATE_RINGS_COMMAND: &str = "crucible-hot-fork-private-rings";
/// Version of the retained private-ring descriptor contract.
pub const QMP_HOT_FORK_PRIVATE_RINGS_SCHEMA_VERSION: u32 = 3;

/// Exact QEMU-owned state for one retained branch-private ring descriptor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QmpHotForkPrivateRingState {
    generation: u64,
    template_generation: u64,
    descriptor_name: Option<QmpDescriptorName>,
    device: u64,
    inode: u64,
    length: u64,
    shrink_sealed: bool,
    source_mapping_bound: bool,
    source_start: u64,
    source_length: u64,
    source_offset: u64,
}

impl QmpHotForkPrivateRingState {
    #[cfg(test)]
    pub(crate) fn one_staged(
        generation: u64,
        descriptor_name: QmpDescriptorName,
        device: u64,
        inode: u64,
        length: u64,
    ) -> Self {
        Self {
            generation,
            template_generation: 0,
            descriptor_name: Some(descriptor_name),
            device,
            inode,
            length,
            shrink_sealed: true,
            source_mapping_bound: false,
            source_start: 0,
            source_length: 0,
            source_offset: 0,
        }
    }

    #[cfg(test)]
    pub(crate) fn one_template_staged(
        generation: u64,
        template_generation: u64,
        descriptor_name: QmpDescriptorName,
        device: u64,
        inode: u64,
        length: u64,
    ) -> Self {
        let mut state = Self::one_staged(generation, descriptor_name, device, inode, length);
        state.template_generation = template_generation;
        state.source_mapping_bound = true;
        state.source_start = 4096;
        state.source_length = length;
        state
    }

    /// Returns the process-local mutation generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the exact template generation that admitted this descriptor.
    ///
    /// Zero means the descriptor was staged outside a template transaction.
    #[must_use]
    pub const fn template_generation(&self) -> u64 {
        self.template_generation
    }

    /// Returns whether QEMU retains an independently duplicated descriptor.
    #[must_use]
    pub const fn staged(&self) -> bool {
        self.descriptor_name.is_some()
    }

    /// Returns the exact standard-QMP name while a descriptor is staged.
    #[must_use]
    pub const fn descriptor_name(&self) -> Option<&QmpDescriptorName> {
        self.descriptor_name.as_ref()
    }

    /// Returns the authenticated backing device number, or zero when absent.
    #[must_use]
    pub const fn device(&self) -> u64 {
        self.device
    }

    /// Returns the authenticated backing inode number, or zero when absent.
    #[must_use]
    pub const fn inode(&self) -> u64 {
        self.inode
    }

    /// Returns the authenticated descriptor length, or zero when absent.
    #[must_use]
    pub const fn length(&self) -> u64 {
        self.length
    }

    /// Returns whether QEMU observed `F_SEAL_SHRINK` at descriptor adoption.
    #[must_use]
    pub const fn shrink_sealed(&self) -> bool {
        self.shrink_sealed
    }

    /// Returns whether QEMU authenticated the template's exact source VMA.
    #[must_use]
    pub const fn source_mapping_bound(&self) -> bool {
        self.source_mapping_bound
    }

    /// Returns the source VMA start address, or zero when it is not bound.
    #[must_use]
    pub const fn source_start(&self) -> u64 {
        self.source_start
    }

    /// Returns the source VMA length, or zero when it is not bound.
    #[must_use]
    pub const fn source_length(&self) -> u64 {
        self.source_length
    }

    /// Returns the source VMA file offset, or zero when it is not bound.
    #[must_use]
    pub const fn source_offset(&self) -> u64 {
        self.source_offset
    }
}

pub(crate) fn parse_hot_fork_private_ring_state(
    value: &Value,
) -> Result<QmpHotForkPrivateRingState, QmpError> {
    let malformed = || QmpError::MalformedTypedResponse {
        command: QmpCommandKind::HotForkPrivateRings,
        response: value.to_string(),
    };
    let object = value.as_object().ok_or_else(&malformed)?;
    let required = [
        "schema-version",
        "generation",
        "template-generation",
        "staged",
        "device",
        "inode",
        "length",
        "shrink-sealed",
        "source-mapping-bound",
        "source-start",
        "source-length",
        "source-offset",
        "disposition-complete",
        "readiness-proof-acknowledged",
    ];
    let has_descriptor_name = object.contains_key("fdname");
    if object.len() != required.len() + usize::from(has_descriptor_name)
        || !required.iter().all(|field| object.contains_key(*field))
    {
        return Err(malformed());
    }

    let schema_version = object
        .get("schema-version")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let generation = object
        .get("generation")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let template_generation = object
        .get("template-generation")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let staged = object
        .get("staged")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let descriptor_name = object
        .get("fdname")
        .map(|name| {
            name.as_str()
                .ok_or_else(&malformed)
                .and_then(|name| QmpDescriptorName::new(name).map_err(|_error| malformed()))
        })
        .transpose()?;
    let device = object
        .get("device")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let inode = object
        .get("inode")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let length = object
        .get("length")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let shrink_sealed = object
        .get("shrink-sealed")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let source_mapping_bound = object
        .get("source-mapping-bound")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let source_start = object
        .get("source-start")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let source_length = object
        .get("source-length")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let source_offset = object
        .get("source-offset")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let disposition_complete = object
        .get("disposition-complete")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let readiness_proof_acknowledged = object
        .get("readiness-proof-acknowledged")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;

    let shape_valid = schema_version == u64::from(QMP_HOT_FORK_PRIVATE_RINGS_SCHEMA_VERSION)
        && !disposition_complete
        && !readiness_proof_acknowledged
        && staged == descriptor_name.is_some()
        && if staged {
            generation != 0
                && inode != 0
                && length != 0
                && shrink_sealed
                && (source_mapping_bound == (template_generation != 0))
                && if source_mapping_bound {
                    source_start != 0
                        && source_length == length
                        && source_offset == 0
                } else {
                    source_start == 0 && source_length == 0 && source_offset == 0
                }
        } else {
            template_generation == 0
                && descriptor_name.is_none()
                && device == 0
                && inode == 0
                && length == 0
                && !shrink_sealed
                && !source_mapping_bound
                && source_start == 0
                && source_length == 0
                && source_offset == 0
        };
    if !shape_valid {
        return Err(malformed());
    }

    Ok(QmpHotForkPrivateRingState {
        generation,
        template_generation,
        descriptor_name,
        device,
        inode,
        length,
        shrink_sealed,
        source_mapping_bound,
        source_start,
        source_length,
        source_offset,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::parse_hot_fork_private_ring_state;

    fn template_stage() -> serde_json::Value {
        json!({
            "schema-version": 3,
            "generation": 7,
            "template-generation": 11,
            "staged": true,
            "fdname": "private-rings",
            "device": 4,
            "inode": 5,
            "length": 4096,
            "shrink-sealed": true,
            "source-mapping-bound": true,
            "source-start": 8192,
            "source-length": 4096,
            "source-offset": 0,
            "disposition-complete": false,
            "readiness-proof-acknowledged": false,
        })
    }

    #[test]
    fn template_stage_requires_exact_source_mapping_basis() {
        let exact = parse_hot_fork_private_ring_state(&template_stage())
            .expect("exact source mapping should parse");
        assert!(exact.source_mapping_bound());
        assert_eq!(exact.source_start(), 8192);
        assert_eq!(exact.source_length(), 4096);
        assert_eq!(exact.source_offset(), 0);

        let mut wrong_length = template_stage();
        wrong_length["source-length"] = json!(8192);
        assert!(parse_hot_fork_private_ring_state(&wrong_length).is_err());

        let mut unbound_template = template_stage();
        unbound_template["source-mapping-bound"] = json!(false);
        unbound_template["source-start"] = json!(0);
        unbound_template["source-length"] = json!(0);
        assert!(parse_hot_fork_private_ring_state(&unbound_template).is_err());
    }
}
