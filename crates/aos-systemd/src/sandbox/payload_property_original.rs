//! Retains the original payload unit property and native descriptor prefix.
//!
//! This mechanical destination does not authorize a launch. The actual Host
//! loan prepays it before construction, and keeps it through submission/posts.

use std::sync::Arc;
use zbus::zvariant::{Fd, OwnedValue, Value};

use super::{Error, Result, SandboxDescriptorPath, SandboxUnitSpec, TransientProperty};

/// Retains one reached payload property program and its exact source objects.
#[derive(Default)]
pub struct PayloadUnitPropertyOriginalV2 {
    pub(super) properties: Vec<TransientProperty>,
    pub(super) active_descriptors: Vec<(Fd<'static>, String)>,
    pub(super) native_failure: Option<std::io::Error>,
    pub(super) native_operation: Option<&'static str>,
    specification: Option<SandboxUnitSpec>,
    failure: Option<Error>,
    entered: bool,
    completed: bool,
}

impl PayloadUnitPropertyOriginalV2 {
    /// Constructs inert destinations without duplicating any descriptor.
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Bounds the complete fixed property program before catalog construction.
    ///
    /// The returned bytes include the same compiled command/spec caps, actual
    /// property/model construction overlap, partial FD roles and owned errors.
    /// Files cover seven possible reached duplicates. Namespace entries count
    /// actual emitted property/array/record names, never Rust fields or Arcs.
    #[must_use]
    pub fn receiving_obligations_v2() -> Option<(usize, usize, usize)> {
        use std::mem::size_of;
        let properties = super::payload_root_continuity::property_count_v2();
        let model_cells = properties.checked_mul(32)?
            .checked_add(super::MAX_ARGUMENTS.checked_add(1)?.checked_mul(16)?)?
            .checked_add(super::MAX_DEVICES.checked_mul(16)?)?;
        let memory = size_of::<Self>().checked_mul(2)?
            .checked_add(SandboxUnitSpec::construction_receiving_bytes_v2()?)?
            .checked_add(model_cells.checked_mul(size_of::<Value<'static>>())?.checked_mul(3)?)?
            .checked_add(super::MAX_ARGUMENT_BYTES.checked_mul(8)?)?
            .checked_add(super::payload_root_continuity::property_literal_bytes_v2()?.checked_mul(8)?)?
            .checked_add(properties.checked_mul(2 * size_of::<TransientProperty>())?)?
            .checked_add(7 * 2 * size_of::<(Fd<'static>, String)>())?
            .checked_add(64 * 1024)?;
        Some((memory, 7, super::payload_root_continuity::property_namespace_entries_v2()?))
    }

    /// Bounds the complete selected StartTransientUnit request before catalog IO.
    ///
    /// Uses the same compiled argument caps, generated unit/proc aliases, full
    /// fixed property vocabulary and canonical D-Bus framing. It is a wire
    /// ceiling, separate from the property/SDK memory and native FD invoices.
    #[must_use]
    pub fn maximum_encoded_request_bytes_v2() -> Option<usize> {
        super::payload_root_continuity::maximum_encoded_request_bytes_v2()
    }

    /// Executes the sole existing property program once on the actual spec.
    ///
    /// # Errors
    /// Rejects reentry or any original compiler/native clone failure. Every
    /// earlier property/descriptor and the exact first cause stay resident.
    pub fn prepare_once_v2(&mut self, specification: &SandboxUnitSpec) -> Result<()> {
        if self.entered { return Err(Error::HostLaunchRetained("payload properties reentry")); }
        self.entered = true;
        self.specification = Some(specification.clone());
        self.properties = Vec::with_capacity(super::payload_root_continuity::property_count_v2());
        self.active_descriptors = Vec::with_capacity(7);
        match super::payload_root_continuity::properties_retaining_v2(specification, self) {
            Ok(()) => { self.completed = true; Ok(()) }
            Err(error) => {
                self.failure = Some(error);
                Err(Error::HostLaunchRetained("payload properties"))
            }
        }
    }

    /// Borrows the exact first native cause, or original compiler failure.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.native_failure.as_ref().map(|cause| cause as _)
            .or_else(|| self.failure.as_ref().map(|cause| cause as _))
    }

    pub(super) fn completed_properties_v2(&self, specification: &SandboxUnitSpec) -> Result<&[TransientProperty]> {
        if !self.completed || self.failure.is_some() || self.native_failure.is_some() {
            return Err(Error::HostLaunchRetained("payload properties incomplete"));
        }
        let original = self.specification.as_ref()
            .ok_or(Error::HostLaunchRetained("payload specification missing"))?;
        if original != specification || !same_source_pins_v2(original, specification) {
            return Err(Error::HostLaunchRetained("payload property sources changed"));
        }
        Ok(&self.properties)
    }
}

fn source_pins_v2(specification: &SandboxUnitSpec) -> [Option<&SandboxDescriptorPath>; 9] {
    let guest = specification.guest_agent_descriptors.as_ref();
    [
        Some(&specification.paths.root_pin),
        Some(&specification.paths._network_pin),
        Some(&specification.command._executable_pin),
        specification.paths.attachment_anchor_pin.as_ref(),
        specification.paths.attachment_anchor_namespace_pin.as_ref(),
        guest.map(|guest| &guest.channel),
        guest.map(|guest| &guest.provisioning),
        guest.map(|guest| &guest.attach_trust),
        specification.host_canary_report.as_ref(),
    ]
}

fn same_source_pins_v2(first: &SandboxUnitSpec, second: &SandboxUnitSpec) -> bool {
    source_pins_v2(first).into_iter().zip(source_pins_v2(second)).all(|(first, second)| {
        match (first, second) {
            (Some(first), Some(second)) => Arc::ptr_eq(&first.pin, &second.pin),
            (None, None) => true,
            _ => false,
        }
    })
}

// Every descriptor is already owned and reached through the original clone
// recipe. Move those exact FDs into the ordinary Value encoder; a second
// fallible ownership-promotion walk would create an unretained native prefix.
pub(super) fn owned_open_files_v2(
    name: &str,
    descriptors: Vec<(Fd<'static>, String)>,
) -> Result<TransientProperty> {
    Ok((name.to_owned(), OwnedValue::from_static_value(Value::from(descriptors))))
}
