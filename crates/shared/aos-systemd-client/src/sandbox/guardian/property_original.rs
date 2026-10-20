//! Owns the existing Guardian transfer and property prefix before submission.
//!
//! One body serves ordinary and retained disposition. Selected preparation
//! moves the exact eleven native outputs into the same owned FD property;
//! ordinary preparation keeps its existing conversion/drop boundary.

use std::os::fd::{BorrowedFd, OwnedFd};
use zbus::zvariant::{Fd, OwnedValue, Value};
use super::*;
use crate::error::Result;
use crate::manager_proxy::TransientProperty;

const PROPERTY_COUNT_V2: usize = 46;
// Conservative aggregate UTF-8 bytes of the sole existing property recipe's
// fixed literals. Dynamic path/incarnation/binding text is counted separately.
const FIXED_PROPERTY_TEXT_BYTES_V2: usize = 900;

pub(super) struct CredentialTransferOriginalV2 {
    pub(super) checks: [credential_original::DescriptorCheckOriginalV2; 10],
    pub(super) duplicates: [Option<std::io::Result<OwnedFd>>; 10],
    pub(super) descriptors: Vec<(Fd<'static>, String)>,
    pub(super) entered: bool,
    pub(super) first_index: usize,
    pub(super) returned: Option<Result<()>>,
}

impl CredentialTransferOriginalV2 {
    pub(super) fn new() -> Self {
        Self {
            checks: std::array::from_fn(|_| credential_original::DescriptorCheckOriginalV2::default()),
            duplicates: std::array::from_fn(|_| None), descriptors: Vec::new(),
            entered: false, first_index: 0, returned: None,
        }
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if self.returned.as_ref().is_none_or(Result::is_ok) { return None; }
        self.checks[self.first_index].failure()
            .or_else(|| failed(&self.duplicates[self.first_index]))
            .or_else(|| failed(&self.returned))
    }
}

#[derive(Clone, Copy)]
enum PropertyFrontierV2 { Executable, Credentials, Properties }

/// Keeps actual failed executable, credential transfers and owned FD properties.
///
/// Construction/admission are distinct: this inert DATA owner grants neither
/// launch nor manager authority. The real enclosing role pays its passive
/// complete geometry before constructing it or preparing the specification.
pub struct GuardianUnitPropertyOriginalV2 {
    executable: GuardianExecutableValidationOriginalV2,
    executable_duplicate: Option<std::io::Result<OwnedFd>>,
    credentials: CredentialTransferOriginalV2,
    descriptors: Vec<(Fd<'static>, String)>,
    properties: Vec<TransientProperty>,
    entered: bool,
    frontier: PropertyFrontierV2,
    returned: Option<Result<()>>,
}

impl GuardianUnitPropertyOriginalV2 {
    /// Creates empty native destinations without allocation or IO.
    #[must_use]
    pub fn new() -> Self {
        Self {
            executable: GuardianExecutableValidationOriginalV2::new(),
            executable_duplicate: None,
            credentials: CredentialTransferOriginalV2::new(),
            descriptors: Vec::new(), properties: Vec::new(), entered: false,
            frontier: PropertyFrontierV2::Executable, returned: None,
        }
    }

    /// Bounds the same recipe before the path-bearing specification exists.
    ///
    /// `path_bytes` is the actual already-held Guardian launcher path length.
    /// Eleven successful transfer outputs and the two failed-read lanes remain
    /// separate from the specification's input pins. No Rust field is billed
    /// as a namespace entry, and no descriptor/account is constructed here.
    #[must_use]
    pub fn receiving_obligations_for_path_v2(path_bytes: usize) -> Option<(usize, usize, usize)> {
        let executable = GuardianExecutableValidationOriginalV2::receiving_obligations_v2()?.0;
        let text = property_text_bytes_for_path_v2(path_bytes)?;
        let properties = PROPERTY_COUNT_V2.checked_mul(std::mem::size_of::<TransientProperty>())?;
        let transfer = 22_usize.checked_mul(std::mem::size_of::<(Fd<'static>, String)>())?;
        let bytes = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(executable)?
            .checked_add(usize::try_from(MAXIMUM_PLAN_BYTES).ok()?.checked_mul(2)?)?
            .checked_add(properties.checked_mul(4)?)?
            .checked_add(transfer)?.checked_add(text.checked_mul(4)?)?;
        Some((bytes, 13, 0))
    }

    /// Bounds the same Guardian's complete StartTransientUnit wire request.
    ///
    /// Uses the shared property text/path recipe, all fixed nested array rows
    /// and eleven descriptor roles. This is checked representation DATA only;
    /// property construction, native duplicates and SDK storage stay separate.
    /// Returns `None` when the actual path length or checked sum overflows.
    #[must_use]
    pub fn maximum_encoded_request_for_path_v2(path_bytes: usize) -> Option<usize> {
        let text = property_text_bytes_for_path_v2(path_bytes)?;
        let filter_rows = GUARDIAN_ALLOWED_ADDRESS_FAMILIES.len()
            .checked_add(GUARDIAN_ALLOWED_SYSCALLS.len())?
            .checked_add(GUARDIAN_DENIED_SOCKET_OPERATIONS.len())?;
        // StateDirectory, architecture, inaccessible path, two environment
        // strings, the ExecStart tuple/two argv strings and three filter tuples.
        let rows = PROPERTY_COUNT_V2.checked_add(filter_rows)?
            .checked_add(GuardianCredentialRole::ALL.len().checked_add(1)?)?
            .checked_add(1 + 1 + 1 + 2 + 1 + 2 + 3)?;
        let unit_text = super::super::GUARD_PREFIX.len().checked_add(32)?
            .checked_add(super::super::UNIT_SUFFIX.len())?;
        // Every fixed scalar/array row has at most 32 framing/alignment bytes;
        // named variants additionally receive 64. The fixed request header
        // covers eight maximal 255-byte D-Bus name/signature fields separately.
        text.checked_add(unit_text)?.checked_add("replace".len())?
            .checked_add(rows.checked_mul(32)?)?
            .checked_add(PROPERTY_COUNT_V2.checked_mul(64)?)?
            .checked_add(16 + 8 * (8 + 4 + 255 + 1))
    }

    /// Prepares the same fixed property recipe while retaining native failures.
    ///
    /// # Errors
    /// Refuses reentry or the same native/protection/property failures as the
    /// ordinary recipe. Exact causes remain borrowed through [`Self::failure`].
    pub fn prepare_once_v2(&mut self, spec: &GuardianUnitSpec) -> Result<()> {
        if self.entered { return Err(invalid("guardian property preparation is already entered")); }
        self.entered = true;
        self.returned = Some(body(spec, self, true));
        match self.returned.as_ref() {
            Some(Ok(())) => Ok(()),
            Some(Err(_)) => Err(invalid("guardian property preparation failed; original retained")),
            None => std::process::abort(),
        }
    }

    /// Borrows the actual chronological native/semantic preparation failure.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if self.returned.as_ref().is_none_or(Result::is_ok) { return None; }
        let actual = match self.frontier {
            PropertyFrontierV2::Executable => self.executable.failure()
                .or_else(|| failed(&self.executable_duplicate)),
            PropertyFrontierV2::Credentials => self.credentials.failure(),
            PropertyFrontierV2::Properties => None,
        };
        actual.or_else(|| failed(&self.returned))
    }

    #[cfg(test)]
    pub(super) fn retained_transfer_counts_v2(&self) -> (usize, usize) {
        (self.descriptors.len(), self.credentials.descriptors.len())
    }

    pub(super) fn properties(&self) -> Result<&[TransientProperty]> {
        if !matches!(self.returned, Some(Ok(()))) {
            return Err(invalid("guardian properties are not complete"));
        }
        Ok(&self.properties)
    }
}

fn property_text_bytes_for_path_v2(path_bytes: usize) -> Option<usize> {
    let role_text = GuardianCredentialRole::ALL.iter().try_fold(
        GUARDIAN_EXECUTABLE_DESCRIPTOR_NAME.len(), |sum, role| sum.checked_add(role.as_str().len()),
    )?;
    let unit_text = super::super::UNIT_PREFIX.len().checked_add(32)?
        .checked_add(super::super::UNIT_SUFFIX.len())?;
    let generated_text = GUARDIAN_STATE_PREFIX.len().checked_add(33)?
        .checked_add(GUARDIAN_ENVIRONMENT_PREFIX.len().checked_add(32)?)?
        .checked_add(GUARDIAN_BINDING_PREFIX.len().checked_add(64)?)?
        .checked_add(unit_text)?;
    let fixed_values = GUARDIAN_ALLOWED_ADDRESS_FAMILIES.iter()
        .chain(GUARDIAN_ALLOWED_SYSCALLS).chain(GUARDIAN_DENIED_SOCKET_OPERATIONS)
        .try_fold(GUARDIAN_SLICE.len().checked_add(GUARDIAN_EXECUTABLE_LAUNCH_ARGUMENT.len())?,
            |sum, value| sum.checked_add(value.len()))?;
    FIXED_PROPERTY_TEXT_BYTES_V2.checked_add(fixed_values)?
        .checked_add(generated_text)?
        .checked_add(role_text)?.checked_add(path_bytes.checked_mul(3)?)
}

impl Default for GuardianUnitPropertyOriginalV2 {
    fn default() -> Self { Self::new() }
}

fn failed<T, E: std::error::Error + 'static>(
    slot: &Option<std::result::Result<T, E>>,
) -> Option<&(dyn std::error::Error + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}

pub(super) fn duplicate(
    descriptor: BorrowedFd<'_>,
    destination: Option<&mut Option<std::io::Result<OwnedFd>>>,
    label: &'static str,
) -> Result<OwnedFd> {
    match descriptor.try_clone_to_owned() {
        Ok(descriptor) => Ok(descriptor),
        Err(cause) => {
            let returned = invalid(format!("{label}: {cause}"));
            if let Some(destination) = destination { *destination = Some(Err(cause)); }
            Err(returned)
        }
    }
}

pub(super) fn construct(spec: &GuardianUnitSpec) -> Result<Vec<TransientProperty>> {
    let mut local = GuardianUnitPropertyOriginalV2::new();
    body(spec, &mut local, false)?;
    Ok(std::mem::take(&mut local.properties))
}

fn body(spec: &GuardianUnitSpec, original: &mut GuardianUnitPropertyOriginalV2, retained: bool) -> Result<()> {
    let environment = format!("{GUARDIAN_ENVIRONMENT_PREFIX}{}", spec.incarnation_hex);
    let binding = format!(
        "{GUARDIAN_BINDING_PREFIX}{}",
        crate::sandbox::encode_hex32(spec.binding)
    );
    original.descriptors = Vec::with_capacity(GuardianCredentialRole::ALL.len() + 1);
    original.frontier = PropertyFrontierV2::Executable;
    original.descriptors.push(spec.executable.transferred_engine_v2(
        if retained { Some((&mut original.executable, &mut original.executable_duplicate)) } else { None },
    )?);
    original.frontier = PropertyFrontierV2::Credentials;
    let credentials = spec.credentials.transferred_engine_v2(
        if retained { Some(&mut original.credentials) } else { None },
    )?;
    original.descriptors.extend(credentials);
    let state_directory = format!("{GUARDIAN_STATE_PREFIX}/{}", spec.incarnation_hex);
    original.frontier = PropertyFrontierV2::Properties;
    original.properties = Vec::with_capacity(PROPERTY_COUNT_V2);
    original.properties.push(string_property("Description", format!("AOS lease guardian {}", spec.name)));
    original.properties.push(string_property("Type", "notify"));
    original.properties.push(string_property("NotifyAccess", "main"));
    original.properties.push(string_property("Slice", GUARDIAN_SLICE));
    original.properties.push(string_property("Restart", "no"));
    original.properties.push(u64_property("StartLimitIntervalUSec", u64::MAX));
    original.properties.push(u32_property("StartLimitBurst", 1));
    original.properties.push(string_property("CollectMode", "inactive-or-failed"));
    original.properties.push(bool_property("DynamicUser", true));
    original.properties.push(string_array_property("StateDirectory", vec![state_directory])?);
    original.properties.push(u32_property("StateDirectoryMode", 0o700));
    original.properties.push(u32_property("UMask", 0o077));
    original.properties.push(u64_property("CapabilityBoundingSet", 0));
    original.properties.push(u64_property("AmbientCapabilities", 0));
    original.properties.push(bool_property("NoNewPrivileges", true));
    original.properties.push(complex_property(
            "RestrictAddressFamilies",
            (
                true,
                GUARDIAN_ALLOWED_ADDRESS_FAMILIES
                    .iter()
                    .map(|value| (*value).to_owned())
                    .collect::<Vec<_>>(),
            ),
        )?);
    original.properties.push(complex_property(
            "SystemCallFilter",
            (
                true,
                GUARDIAN_ALLOWED_SYSCALLS
                    .iter()
                    .map(|value| (*value).to_owned())
                    .collect::<Vec<_>>(),
            ),
        )?);
    original.properties.push(complex_property(
            "SystemCallFilter",
            (
                false,
                GUARDIAN_DENIED_SOCKET_OPERATIONS
                    .iter()
                    .map(|value| (*value).to_owned())
                    .collect::<Vec<_>>(),
            ),
        )?);
    original.properties.push(string_array_property("SystemCallArchitectures", vec!["native".to_owned()])?);
    original.properties.push(string_property("ProtectSystem", "strict"));
    original.properties.push(string_property("ProtectHome", "yes"));
    original.properties.push(bool_property("PrivateNetwork", true));
    original.properties.push(bool_property("PrivateIPC", true));
    original.properties.push(bool_property("PrivateTmp", true));
    original.properties.push(bool_property("PrivateDevices", true));
    original.properties.push(bool_property("ProtectKernelTunables", true));
    original.properties.push(bool_property("ProtectKernelModules", true));
    original.properties.push(bool_property("ProtectControlGroups", true));
    original.properties.push(bool_property("ProtectClock", true));
    original.properties.push(u64_property("RestrictNamespaces", 0));
    original.properties.push(bool_property("LockPersonality", true));
    original.properties.push(bool_property("MemoryDenyWriteExecute", true));
    original.properties.push(bool_property("RestrictRealtime", true));
    original.properties.push(bool_property("RestrictSUIDSGID", true));
    original.properties.push(string_array_property(
            "InaccessiblePaths",
            vec!["/run/dbus/system_bus_socket".to_owned()],
        )?);
    original.properties.push(if retained {
        ("ExtraFileDescriptors".to_owned(), OwnedValue::from_static_value(
            Value::from(std::mem::take(&mut original.descriptors)),
        ))
    } else {
        complex_property("ExtraFileDescriptors", std::mem::take(&mut original.descriptors))?
    });
    original.properties.push(string_array_property("Environment", vec![environment, binding])?);
    original.properties.push(bool_property("SetLoginEnvironment", false));
    original.properties.push(u64_property(
            "TimeoutStartUSec",
            duration_micros(spec.timeout_start, "guardian start timeout")?,
        ));
    original.properties.push(exec_property(
            &spec.executable_path,
            vec![
                spec.executable_path.clone(),
                GUARDIAN_EXECUTABLE_LAUNCH_ARGUMENT.to_owned(),
            ],
        )?);

    if let Some(limits) = spec.host_canary_limits {
        let cpu_per_second = limits[0].checked_mul(10)
            .ok_or_else(|| invalid("Host canary Guardian CPU limit overflow"))?;
        original.properties.extend([
            u64_property("CPUQuotaPerSecUSec", cpu_per_second),
            u64_property("CPUQuotaPeriodUSec", 100_000),
            u64_property("MemoryMax", limits[1]),
            u64_property("TasksMax", limits[2]),
            u64_property("LimitNOFILE", limits[3]),
            u64_property("LimitNOFILESoft", limits[3]),
        ]);
    }
    Ok(())
}
