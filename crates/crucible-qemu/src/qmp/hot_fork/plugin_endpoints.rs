//! QEMU-owned retention of branch-private plugin control and wake endpoints.

use serde_json::Value;

use crate::qmp::{QmpCommandKind, QmpDescriptorName, QmpError};

/// QMP command that retains or releases one authenticated plugin endpoint pair.
pub const QMP_HOT_FORK_PLUGIN_ENDPOINTS_COMMAND: &str = "crucible-hot-fork-plugin-endpoints";
/// Version of the retained plugin-endpoint contract.
pub const QMP_HOT_FORK_PLUGIN_ENDPOINTS_SCHEMA_VERSION: u32 = 1;

/// Exact Linux identities for one branch-private plugin endpoint pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QmpHotForkPluginEndpointIdentity {
    control_socket_cookie: u64,
    wake_eventfd_id: u64,
}

impl QmpHotForkPluginEndpointIdentity {
    /// Creates an exact nonzero Linux endpoint identity.
    ///
    /// Returns `None` when either kernel identity is zero.
    #[must_use]
    pub const fn new(control_socket_cookie: u64, wake_eventfd_id: u64) -> Option<Self> {
        if control_socket_cookie == 0 || wake_eventfd_id == 0 {
            return None;
        }
        Some(Self {
            control_socket_cookie,
            wake_eventfd_id,
        })
    }

    /// Returns the exact Linux `SO_COOKIE` for the control socket.
    #[must_use]
    pub const fn control_socket_cookie(self) -> u64 {
        self.control_socket_cookie
    }

    /// Returns the exact Linux `/proc/self/fdinfo` eventfd identity.
    #[must_use]
    pub const fn wake_eventfd_id(self) -> u64 {
        self.wake_eventfd_id
    }
}

/// Exact QEMU-owned state for retained branch-private plugin endpoints.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QmpHotForkPluginEndpointState {
    generation: u64,
    control_name: Option<QmpDescriptorName>,
    wake_name: Option<QmpDescriptorName>,
    identity: Option<QmpHotForkPluginEndpointIdentity>,
    private_ring_generation: u64,
}

impl QmpHotForkPluginEndpointState {
    /// Returns the process-local mutation generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns whether QEMU retains both independently duplicated endpoints.
    #[must_use]
    pub const fn staged(&self) -> bool {
        self.identity.is_some()
    }

    /// Returns the exact standard-QMP control name while staged.
    #[must_use]
    pub const fn control_name(&self) -> Option<&QmpDescriptorName> {
        self.control_name.as_ref()
    }

    /// Returns the exact standard-QMP wake name while staged.
    #[must_use]
    pub const fn wake_name(&self) -> Option<&QmpDescriptorName> {
        self.wake_name.as_ref()
    }

    /// Returns the authenticated kernel-object identities while staged.
    #[must_use]
    pub const fn identity(&self) -> Option<QmpHotForkPluginEndpointIdentity> {
        self.identity
    }

    /// Returns the exact retained private-ring generation bound at staging.
    #[must_use]
    pub const fn private_ring_generation(&self) -> u64 {
        self.private_ring_generation
    }
}

pub(crate) fn parse_hot_fork_plugin_endpoint_state(
    value: &Value,
) -> Result<QmpHotForkPluginEndpointState, QmpError> {
    let malformed = || QmpError::MalformedTypedResponse {
        command: QmpCommandKind::HotForkPluginEndpoints,
        response: value.to_string(),
    };
    let object = value.as_object().ok_or_else(&malformed)?;
    let required = [
        "schema-version",
        "generation",
        "staged",
        "control-socket-cookie",
        "wake-eventfd-id",
        "private-ring-generation",
        "control-unix-stream",
        "wake-eventfd",
        "disposition-complete",
        "readiness-proof-acknowledged",
    ];
    let has_control_name = object.contains_key("control-fdname");
    let has_wake_name = object.contains_key("wake-fdname");
    if object.len() != required.len() + usize::from(has_control_name) + usize::from(has_wake_name)
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
    let staged = object
        .get("staged")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let parse_name = |field| {
        object
            .get(field)
            .map(|name| {
                name.as_str()
                    .ok_or_else(&malformed)
                    .and_then(|name| QmpDescriptorName::new(name).map_err(|_error| malformed()))
            })
            .transpose()
    };
    let control_name = parse_name("control-fdname")?;
    let wake_name = parse_name("wake-fdname")?;
    let control_socket_cookie = object
        .get("control-socket-cookie")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let wake_eventfd_id = object
        .get("wake-eventfd-id")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let private_ring_generation = object
        .get("private-ring-generation")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let control_unix_stream = object
        .get("control-unix-stream")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let wake_eventfd = object
        .get("wake-eventfd")
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

    let names_present = control_name.is_some() && wake_name.is_some();
    let names_distinct = control_name != wake_name;
    let shape_valid = schema_version == u64::from(QMP_HOT_FORK_PLUGIN_ENDPOINTS_SCHEMA_VERSION)
        && !disposition_complete
        && !readiness_proof_acknowledged
        && staged == names_present
        && has_control_name == has_wake_name
        && if staged {
            generation != 0
                && names_distinct
                && control_socket_cookie != 0
                && wake_eventfd_id != 0
                && private_ring_generation != 0
                && control_unix_stream
                && wake_eventfd
        } else {
            control_name.is_none()
                && wake_name.is_none()
                && control_socket_cookie == 0
                && wake_eventfd_id == 0
                && private_ring_generation == 0
                && !control_unix_stream
                && !wake_eventfd
        };
    if !shape_valid {
        return Err(malformed());
    }

    let identity = if staged {
        Some(QmpHotForkPluginEndpointIdentity {
            control_socket_cookie,
            wake_eventfd_id,
        })
    } else {
        None
    };
    Ok(QmpHotForkPluginEndpointState {
        generation,
        control_name,
        wake_name,
        identity,
        private_ring_generation,
    })
}
