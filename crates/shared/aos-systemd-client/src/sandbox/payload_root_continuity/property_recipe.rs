//! Shares the complete fixed payload property program and native clone order.
//! Local destinations preserve ordinary consuming behavior. Retained destinations
//! park the actual property/FD prefix before every later fallible operation.

macro_rules! payload_property_table_v2 {
    (Local, $original:ident, $capacity:expr) => { Vec::with_capacity($capacity) };
    (Retained, $original:ident, $capacity:expr) => { &mut $original.properties };
}

macro_rules! payload_descriptor_table_v2 {
    (Local, $original:ident, $root:ident, $role:expr) => { vec![(Fd::from($root), $role)] };
    (Retained, $original:ident, $root:ident, $role:expr) => {{
        $original.active_descriptors.push((Fd::from($root), $role));
        &mut $original.active_descriptors
    }};
}

macro_rules! payload_clone_v2 {
    (Local, $original:ident, $operation:expr, $mapping:expr, $label:expr) => {
        $operation.map_err($mapping)?
    };
    (Retained, $original:ident, $operation:expr, $mapping:expr, $label:expr) => {
        match $operation {
            Ok(descriptor) => descriptor,
            Err(error) => {
                $original.native_failure = Some(error);
                $original.native_operation = Some($label);
                return Err(crate::Error::HostLaunchRetained($label));
            }
        }
    };
}

macro_rules! payload_anchor_checkpoint_v2 {
    (Local, $descriptors:ident, $anchor:ident, $role:expr) => {};
    (Retained, $descriptors:ident, $anchor:ident, $role:expr) => {
        $descriptors.push((Fd::from($anchor), $role));
    };
}

macro_rules! payload_anchor_finish_v2 {
    (Local, $descriptors:ident, $anchor:ident, $role:expr) => {
        $descriptors.push((Fd::from($anchor), $role));
    };
    (Retained, $descriptors:ident, $anchor:ident, $role:expr) => {};
}

macro_rules! payload_open_files_v2 {
    (Local, $name:ident, $descriptors:ident) => { complex_property($name, $descriptors) };
    (Retained, $name:ident, $descriptors:ident) => {
        super::payload_property_original::owned_open_files_v2(
            $name, std::mem::take($descriptors),
        )
    };
}

macro_rules! payload_property_finish_v2 {
    (Local, $properties:ident) => { Ok($properties) };
    (Retained, $properties:ident) => { Ok(()) };
}

macro_rules! payload_properties_v2 {
    ($mode:ident, $original:ident, $projection:ident, $spec:ident) => {{
        let spec = $spec;

        let mut argv = Vec::with_capacity(spec.arguments.len() + 1);
        argv.push(spec.command.executable.clone());
        argv.extend(spec.arguments.iter().cloned());

        let mut properties = payload_property_table_v2!($mode, $original, $projection.unit_properties.len());
        for policy in $projection.unit_properties {
            let property = match policy {
                UnitPropertyPolicyV1::Description { name, prefix } => {
                    Some(string_property(name, format!("{prefix}{}", spec.name)))
                }
                UnitPropertyPolicyV1::String { name, value } => Some(string_property(name, value)),
                UnitPropertyPolicyV1::Bool { name, value } => Some(bool_property(name, *value)),
                UnitPropertyPolicyV1::U32 { name, value } => Some(u32_property(name, *value)),
                UnitPropertyPolicyV1::U64 { name, value } => Some(u64_property(name, *value)),
                UnitPropertyPolicyV1::BoolStringArray {
                    name,
                    allow,
                    values,
                } => Some(complex_property(
                    name,
                    (
                        *allow,
                        values
                            .iter()
                            .map(|value| (*value).to_owned())
                            .collect::<Vec<_>>(),
                    ),
                )?),
                UnitPropertyPolicyV1::StringArray { name, values } => Some(string_array_property(
                    name,
                    values
                        .iter()
                        .map(|value| (*value).to_owned())
                        .collect::<Vec<_>>(),
                )?),
                UnitPropertyPolicyV1::StringPairs { name, values } => {
                    let pairs = values
                        .iter()
                        .map(|(first, second)| ((*first).to_owned(), (*second).to_owned()))
                        .collect::<Vec<_>>();
                    Some(complex_property(name, pairs)?)
                }
                UnitPropertyPolicyV1::ExtraFileDescriptors { name } => {
                    // The supervisor cannot dereference the broker's procfs
                    // aliases, so root objects cross D-Bus as named fds.
                    let root_fd = payload_clone_v2!($mode, $original,
                        spec.paths.root_pin.pin.try_clone(),
                        |error| invalid(format!("cannot duplicate nspawn root descriptor: {error}")), "duplicate nspawn root descriptor");
                    let mut descriptors = payload_descriptor_table_v2!($mode, $original,
                        root_fd, $projection.descriptor_roles.root.to_owned());
                    if let Some(anchor) = &spec.paths.attachment_anchor_pin {
                        let source_namespace = spec
                            .paths
                            .attachment_anchor_namespace_pin
                            .as_ref()
                            .ok_or_else(|| {
                                invalid(
                                    "nspawn attachment anchor omitted its source mount namespace",
                                )
                            })?;
                        let anchor_fd = payload_clone_v2!($mode, $original, anchor.pin.try_clone(),
                            |error| invalid(format!("cannot duplicate nspawn attachment-anchor descriptor: {error}")),
                            "duplicate nspawn attachment-anchor descriptor");
                        payload_anchor_checkpoint_v2!($mode, descriptors, anchor_fd,
                            $projection.descriptor_roles.attachment_anchor.to_owned());
                        let source_namespace_fd = payload_clone_v2!($mode, $original,
                            source_namespace.pin.try_clone(),
                            |error| invalid(format!("cannot duplicate nspawn attachment-anchor namespace: {error}")),
                            "duplicate nspawn attachment-anchor namespace");
                        payload_anchor_finish_v2!($mode, descriptors, anchor_fd,
                            $projection.descriptor_roles.attachment_anchor.to_owned());
                        descriptors.push((
                            Fd::from(source_namespace_fd),
                            $projection.descriptor_roles.attachment_anchor_namespace.to_owned(),
                        ));
                    }
                    if let Some(guest) = &spec.guest_agent_descriptors {
                        for (pin, role) in [
                            (&guest.channel, GUEST_CHANNEL_ROLE_V2),
                            (
                                &guest.provisioning,
                                GUEST_PROVISIONING_ROLE_V2,
                            ),
                            (&guest.attach_trust, GUEST_ATTACH_TRUST_ROLE_V2),
                        ] {
                            let descriptor = payload_clone_v2!($mode, $original, pin.pin.try_clone(),
                                |error| invalid(format!("cannot duplicate {role} descriptor: {error}")), role);
                            descriptors.push((Fd::from(descriptor), role.to_owned()));
                        }
                    }
                    if let Some(report) = &spec.host_canary_report {
                        let descriptor = payload_clone_v2!($mode, $original, report.pin.try_clone(),
                            |error| invalid(format!("cannot duplicate Host canary report descriptor: {error}")),
                            "duplicate Host canary report descriptor");
                        descriptors.push((Fd::from(descriptor), spec.host_startup_report_role_v2().to_owned()));
                    }
                    Some(payload_open_files_v2!($mode, name, descriptors)?)
                }
                UnitPropertyPolicyV1::Environment {
                    name,
                    fixed,
                    binding_prefix,
                } => {
                    let mut environment = fixed
                        .iter()
                        .map(|value| (*value).to_owned())
                        .collect::<Vec<_>>();
                    if let Some(binding) = spec.launch_binding {
                        environment.push(format!("{binding_prefix}{}", encode_hex32(binding)));
                    }
                    Some(string_array_property(name, environment)?)
                }
                UnitPropertyPolicyV1::GuardianDependency { name } => Some(string_array_property(
                    name,
                    vec![spec.name.guardian.to_string()],
                )?),
                UnitPropertyPolicyV1::ResourceU64 { name, field } => {
                    let value = match field {
                        ResourceU64FieldV1::TasksMax => spec.resources.tasks_max,
                        ResourceU64FieldV1::MemoryHigh => spec.resources.memory_high_bytes,
                        ResourceU64FieldV1::MemoryMax => spec.resources.memory_max_bytes,
                        ResourceU64FieldV1::CpuWeight => spec.resources.cpu_weight.get(),
                    };
                    Some(u64_property(name, value))
                }
                UnitPropertyPolicyV1::DurationU64 { name, field } => {
                    let (duration, label) = match field {
                        DurationU64FieldV1::TimeoutStart => (spec.timeout_start, "start timeout"),
                        DurationU64FieldV1::TimeoutStop => (spec.timeout_stop, "stop timeout"),
                    };
                    Some(u64_property(name, duration_micros(duration, label)?))
                }
                UnitPropertyPolicyV1::OptionalU64 { name, field } => {
                    let value = match field {
                        OptionalU64FieldV1::CpuQuota => spec
                            .resources
                            .cpu_quota_per_second
                            .map(|quota| duration_micros(quota, "CPU quota"))
                            .transpose()?,
                        OptionalU64FieldV1::IoWeight => spec.resources.io_weight,
                        OptionalU64FieldV1::OpenFiles => spec.resources.open_files,
                    };
                    value.map(|value| u64_property(name, value))
                }
                UnitPropertyPolicyV1::NetworkNamespace { name } => {
                    Some(string_property(name, &spec.paths.network_namespace_path))
                }
                UnitPropertyPolicyV1::ExecStart {
                    name,
                    ignore_failure,
                } => Some(named_exec_property(
                    name,
                    &spec.command.executable,
                    argv.clone(),
                    *ignore_failure,
                )?),
                UnitPropertyPolicyV1::DeviceAllow { name, rules } => {
                    if spec.devices.is_empty() {
                        None
                    } else {
                        let mut allow = Vec::with_capacity(spec.devices.len());
                        for device in &spec.devices {
                            let rule = rules
                                .iter()
                                .find(|rule| rule.device == *device)
                                .ok_or_else(|| {
                                    invalid("device is absent from fixed DeviceAllow policy")
                                })?;
                            allow.push((rule.path.to_owned(), rule.permissions.to_owned()));
                        }
                        Some(complex_property(name, allow)?)
                    }
                }
            };
            if let Some((name, _)) = &property {
                debug_assert_eq!(name, policy.name());
            }
            properties.extend(property);
        }

        payload_property_finish_v2!($mode, properties)
        }};
}
