//! QEMU-owned retention of one branch-private shared-ring descriptor.

use serde_json::Value;

use crate::qmp::{QmpCommandKind, QmpDescriptorName, QmpError};

/// QMP command that retains or releases one authenticated private-ring descriptor.
pub const QMP_HOT_FORK_PRIVATE_RINGS_COMMAND: &str = "crucible-hot-fork-private-rings";
/// Version of the retained private-ring descriptor contract.
pub const QMP_HOT_FORK_PRIVATE_RINGS_SCHEMA_VERSION: u32 = 2;

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
            generation != 0 && inode != 0 && length != 0 && shrink_sealed
        } else {
            template_generation == 0
                && descriptor_name.is_none()
                && device == 0
                && inode == 0
                && length == 0
                && !shrink_sealed
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
    })
}
