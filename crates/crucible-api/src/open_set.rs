//! Open-set API payloads for RFC-0010 command, event, fault, and breakpoint data.
//!
//! The wire model keeps the transport envelope closed while leaving the payload
//! body open. A payload is a dotted `kind` string plus a typed attribute map:
//!
//! ```text
//! kind = "crucible.event.rng_draw"
//! attributes.stream_name = "scheduler"
//! attributes.value = uint(17)
//! ```
//!
//! Event payload kinds and attribute names are adapted directly from
//! [`crucible::event_kind_catalog`]. Commands, faults, and breakpoint conditions
//! use the existing session command table, fault taxonomy keys, and shared
//! predicate vocabulary as their source vocabularies.

use std::collections::BTreeMap;
use std::fmt;

use crucible::{
    Condition, EventAttributeValue, EventLevel, EventPayload, EventSource, Fault, FaultTag,
    Predicate, SchedulerEventLogClass, SchedulerEventLogEntry, event_kind_catalog,
    event_kind_catalog_entry,
};
use crucible_session::{
    BreakpointDisposition, BreakpointPolicy, BreakpointSpec, SessionCommandKind,
};
use thiserror::Error;

use crate::session_mapping::{
    API_COMMAND_MAPPINGS, api_command_for_session_command, session_command_for_api_command,
};

/// Dotted namespace prefix for API command payload kinds.
pub const OPEN_SET_COMMAND_KIND_PREFIX: &str = "crucible.cmd.";
/// Dotted namespace prefix for API breakpoint-condition payload kinds.
pub const OPEN_SET_BREAKPOINT_KIND_PREFIX: &str = "crucible.bp.";
/// Dotted namespace prefix for API fault payload kinds.
pub const OPEN_SET_FAULT_KIND_PREFIX: &str = "crucible.fault.";
/// Dotted namespace prefix for API event payload kinds.
pub const OPEN_SET_EVENT_KIND_PREFIX: &str = "crucible.event.";

/// Category names advertised by `Hello` for open-set payload discovery.
pub const OPEN_SET_CAPABILITY_CATEGORIES: &[&str] = &[
    "crucible.cmd.*",
    "crucible.bp.*",
    "crucible.fault.*",
    "crucible.event.*",
];

/// One open-set payload category carried by the API.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OpenSetPayloadCategory {
    /// Session command payloads sent by a client.
    Command,
    /// Breakpoint predicate payloads sent by a client.
    Breakpoint,
    /// Fault taxonomy payloads sent by a client.
    Fault,
    /// Event-log payloads received by a client.
    Event,
}

impl OpenSetPayloadCategory {
    /// Returns the dotted kind prefix for this category.
    #[must_use]
    pub const fn prefix(self) -> &'static str {
        match self {
            Self::Command => OPEN_SET_COMMAND_KIND_PREFIX,
            Self::Breakpoint => OPEN_SET_BREAKPOINT_KIND_PREFIX,
            Self::Fault => OPEN_SET_FAULT_KIND_PREFIX,
            Self::Event => OPEN_SET_EVENT_KIND_PREFIX,
        }
    }

    /// Returns the category name used in diagnostics.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Command => "command",
            Self::Breakpoint => "breakpoint",
            Self::Fault => "fault",
            Self::Event => "event",
        }
    }
}

impl fmt::Display for OpenSetPayloadCategory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label())
    }
}

/// A typed scalar value inside an open-set attribute map.
#[derive(Clone, Debug, PartialEq)]
pub enum OpenSetAttributeValue {
    /// Boolean scalar.
    Bool(bool),
    /// Signed integer scalar.
    Int(i64),
    /// Unsigned integer scalar.
    Uint(u64),
    /// Wide unsigned integer scalar.
    Uint128(u128),
    /// Deterministic IEEE-754 `f64` bit pattern.
    Float64Bits(u64),
    /// UTF-8 string scalar.
    String(String),
    /// Raw byte scalar.
    Bytes(Vec<u8>),
}

impl OpenSetAttributeValue {
    /// Builds a deterministic floating-point scalar from an `f64`.
    #[must_use]
    pub const fn from_f64(value: f64) -> Self {
        Self::Float64Bits(value.to_bits())
    }

    /// Returns this scalar as an `f64` when it carries a floating-point value.
    #[must_use]
    pub const fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Float64Bits(bits) => Some(f64::from_bits(*bits)),
            Self::Bool(_)
            | Self::Int(_)
            | Self::Uint(_)
            | Self::Uint128(_)
            | Self::String(_)
            | Self::Bytes(_) => None,
        }
    }
}

impl From<&EventAttributeValue> for OpenSetAttributeValue {
    fn from(value: &EventAttributeValue) -> Self {
        match value {
            EventAttributeValue::Bool(value) => Self::Bool(*value),
            EventAttributeValue::U64(value) => Self::Uint(*value),
            EventAttributeValue::U128(value) => Self::Uint128(*value),
            EventAttributeValue::String(value) => Self::String(value.clone()),
            EventAttributeValue::Bytes(value) => Self::Bytes(value.clone()),
            EventAttributeValue::Node(value) => Self::String(value.name.clone()),
            EventAttributeValue::Event(value) => Self::String(value.name.clone()),
            EventAttributeValue::Fault(value) => Self::String(value.name.clone()),
            EventAttributeValue::VirtualTime(value) => Self::Uint(value.ticks),
            EventAttributeValue::Icount(value) => Self::Uint(value.retired),
            EventAttributeValue::Level(value) => Self::String(event_level_label(*value).to_owned()),
        }
    }
}

/// Wire-facing open-set payload.
#[derive(Clone, Debug, PartialEq)]
pub struct OpenSetPayload {
    /// Dotted open-set kind string.
    pub kind: String,
    /// Typed scalar attributes keyed by stable attribute name.
    pub attributes: BTreeMap<String, OpenSetAttributeValue>,
}

impl OpenSetPayload {
    /// Builds an open-set payload from a kind and typed attributes.
    #[must_use]
    pub fn new(
        kind: impl Into<String>,
        attributes: BTreeMap<String, OpenSetAttributeValue>,
    ) -> Self {
        Self {
            kind: kind.into(),
            attributes,
        }
    }

    /// Builds an open-set payload with no attributes.
    #[must_use]
    pub fn empty(kind: impl Into<String>) -> Self {
        Self::new(kind, BTreeMap::new())
    }

    /// Returns one typed attribute by name.
    #[must_use]
    pub fn attribute(&self, name: &str) -> Option<&OpenSetAttributeValue> {
        self.attributes.get(name)
    }
}

/// A known payload kind and its stable attribute names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenSetKindSchema {
    /// Category that owns this kind.
    pub category: OpenSetPayloadCategory,
    /// Dotted kind string.
    pub kind: String,
    /// Attribute names accepted or emitted for this kind.
    pub attributes: Vec<String>,
}

impl OpenSetKindSchema {
    /// Returns whether this schema allows `attribute`.
    #[must_use]
    pub fn allows_attribute(&self, attribute: &str) -> bool {
        self.attributes.iter().any(|candidate| {
            candidate == attribute
                || candidate
                    .strip_suffix(".*")
                    .is_some_and(|prefix| attribute.starts_with(prefix))
        })
    }
}

/// Capability catalog advertised by the current API implementation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenSetCapabilities {
    /// Command kinds accepted by the session command surface.
    pub commands: Vec<OpenSetKindSchema>,
    /// Breakpoint predicate kinds accepted by breakpoint commands.
    pub breakpoints: Vec<OpenSetKindSchema>,
    /// Fault taxonomy kinds accepted by fault-injection commands.
    pub faults: Vec<OpenSetKindSchema>,
    /// Event payload kinds emitted by the unified event log.
    pub event_payloads: Vec<OpenSetKindSchema>,
}

impl OpenSetCapabilities {
    /// Builds the current capability catalog from the existing engine catalogs.
    #[must_use]
    pub fn current() -> Self {
        Self {
            commands: API_COMMAND_MAPPINGS
                .iter()
                .map(|mapping| command_schema(mapping.command_name))
                .collect(),
            breakpoints: BREAKPOINT_KIND_TEMPLATES
                .iter()
                .map(|template| template.schema(OpenSetPayloadCategory::Breakpoint))
                .collect(),
            faults: FAULT_KIND_TEMPLATES
                .iter()
                .map(|template| template.schema(OpenSetPayloadCategory::Fault))
                .collect(),
            event_payloads: event_kind_catalog()
                .iter()
                .map(|entry| OpenSetKindSchema {
                    category: OpenSetPayloadCategory::Event,
                    kind: open_set_kind(OpenSetPayloadCategory::Event, entry.kind()),
                    attributes: entry
                        .attributes()
                        .iter()
                        .map(|attribute| (*attribute).to_owned())
                        .collect(),
                })
                .collect(),
        }
    }

    /// Returns the schemas for one payload category.
    #[must_use]
    pub fn schemas(&self, category: OpenSetPayloadCategory) -> &[OpenSetKindSchema] {
        match category {
            OpenSetPayloadCategory::Command => &self.commands,
            OpenSetPayloadCategory::Breakpoint => &self.breakpoints,
            OpenSetPayloadCategory::Fault => &self.faults,
            OpenSetPayloadCategory::Event => &self.event_payloads,
        }
    }

    /// Returns whether a category advertises `kind`.
    #[must_use]
    pub fn supports_kind(&self, category: OpenSetPayloadCategory, kind: &str) -> bool {
        self.schema_for(category, kind).is_some()
    }

    /// Returns the schema for `kind` in `category`.
    #[must_use]
    pub fn schema_for(
        &self,
        category: OpenSetPayloadCategory,
        kind: &str,
    ) -> Option<&OpenSetKindSchema> {
        self.schemas(category)
            .iter()
            .find(|schema| schema.kind == kind)
    }
}

/// Returns the current open-set capability catalog.
#[must_use]
pub fn current_open_set_capabilities() -> OpenSetCapabilities {
    OpenSetCapabilities::current()
}

/// Returns the dotted API command kind for one session command kind.
#[must_use]
pub fn open_set_command_kind(command: SessionCommandKind) -> Option<String> {
    api_command_for_session_command(command)
        .map(|mapping| open_set_kind(OpenSetPayloadCategory::Command, mapping.command_name))
}

/// Returns the session command kind for one dotted API command kind.
#[must_use]
pub fn session_command_for_open_set_command_kind(kind: &str) -> Option<SessionCommandKind> {
    kind.strip_prefix(OPEN_SET_COMMAND_KIND_PREFIX)
        .filter(|local_kind| !local_kind.is_empty())
        .and_then(session_command_for_api_command)
}

/// Returns the dotted API fault kind for one taxonomy fault.
#[must_use]
pub fn open_set_fault_kind(fault: &Fault) -> String {
    open_set_kind(OpenSetPayloadCategory::Fault, fault.kind_key())
}

/// Builds the API fault payload for a typed fault command.
#[must_use]
pub fn open_set_payload_for_fault(tag: &FaultTag, fault: &Fault) -> OpenSetPayload {
    let mut attributes = BTreeMap::new();
    attributes.insert(
        String::from("tag"),
        OpenSetAttributeValue::String(tag.name.clone()),
    );
    attributes.insert(
        String::from("content_hash"),
        OpenSetAttributeValue::String(fault.content_hash().to_hex()),
    );
    OpenSetPayload::new(open_set_fault_kind(fault), attributes)
}

/// Returns the dotted API breakpoint kind for one shared predicate.
#[must_use]
pub fn open_set_breakpoint_kind(condition: &Condition) -> &'static str {
    match condition {
        Predicate::At { .. } => "crucible.bp.at",
        Predicate::After { .. } => "crucible.bp.after",
        Predicate::Timer { .. } => "crucible.bp.timer",
        Predicate::NetworkMatch { .. } => "crucible.bp.network-match",
        Predicate::ConsoleMatch { .. } => "crucible.bp.console-match",
        Predicate::CoveragePoint { .. } => "crucible.bp.coverage-point",
        Predicate::MemoryPredicate { .. } => "crucible.bp.memory-predicate",
        Predicate::IoPattern { .. } => "crucible.bp.io-pattern",
        Predicate::NodeState { .. } => "crucible.bp.node-state",
        Predicate::AssertionState { .. } => "crucible.bp.assertion-state",
        Predicate::Quiescent => "crucible.bp.quiescent",
        Predicate::FaultActive { .. } => "crucible.bp.fault-active",
        Predicate::Named { .. } => "crucible.bp.named",
        Predicate::GuestMarker { .. } => "crucible.bp.guest-marker",
        Predicate::AllOf { .. } => "crucible.bp.all-of",
        Predicate::AnyOf { .. } => "crucible.bp.any-of",
        Predicate::Once { .. } => "crucible.bp.once",
        Predicate::Not { .. } => "crucible.bp.not",
    }
}

/// Builds the API breakpoint payload for a breakpoint command.
#[must_use]
pub fn open_set_payload_for_breakpoint(spec: &BreakpointSpec) -> OpenSetPayload {
    let mut attributes = BTreeMap::new();
    attributes.insert(
        String::from("predicate"),
        OpenSetAttributeValue::String(spec.predicate.canonical_summary()),
    );
    attributes.insert(
        String::from("policy"),
        OpenSetAttributeValue::String(breakpoint_policy_label(spec.policy).to_owned()),
    );
    attributes.insert(
        String::from("disposition"),
        OpenSetAttributeValue::String(breakpoint_disposition_label(&spec.disposition).to_owned()),
    );
    OpenSetPayload::new(open_set_breakpoint_kind(&spec.predicate), attributes)
}

/// Builds an API event payload from an event-log payload.
#[must_use]
pub fn open_set_payload_from_event_payload(payload: &EventPayload) -> OpenSetPayload {
    let attributes = payload
        .attributes()
        .iter()
        .map(|(name, value)| (name.clone(), OpenSetAttributeValue::from(value)))
        .collect();
    OpenSetPayload::new(
        open_set_kind(OpenSetPayloadCategory::Event, payload.kind()),
        attributes,
    )
}

/// Event-log time coordinate carried by API event envelopes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenSetEventTime {
    /// Scheduler virtual-time ticks.
    pub virtual_time_ticks: u64,
    /// Retired instruction count at the same boundary.
    pub icount_retired: u64,
    /// Node whose retired-instruction counter was sampled.
    pub icount_node: Option<String>,
}

/// Closed event source carried next to an open event payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpenSetEventSource {
    /// Scenario-defined temporal event or fault.
    Scenario {
        /// Event graph id that produced the entry.
        event: String,
    },
    /// Scheduler, temporal graph, fault subsystem, or assertion engine.
    Engine,
    /// VM node or deterministic I/O sub-node.
    Node {
        /// Scenario node that originated the entry.
        node: String,
    },
    /// Guest-observed marker or black-box guest signal.
    Guest {
        /// Scenario node whose guest produced the entry.
        node: String,
    },
    /// Control-plane command.
    Command {
        /// Session-local command correlation id.
        command_id: u64,
    },
}

/// Event-log entry shape delivered by API streams.
#[derive(Clone, Debug, PartialEq)]
pub struct OpenSetEventEnvelope {
    /// Dense event-log sequence number.
    pub sequence: u64,
    /// Event-log time coordinate.
    pub at: OpenSetEventTime,
    /// Closed event-log source.
    pub source: OpenSetEventSource,
    /// Display verbosity level.
    pub level: EventLevel,
    /// Whether the entry is observational instead of causal.
    pub observational: bool,
    /// Open-set event payload.
    pub payload: OpenSetPayload,
}

/// Converts one scheduler event-log entry into its API event envelope.
#[must_use]
pub fn open_set_event_envelope_from_entry(entry: &SchedulerEventLogEntry) -> OpenSetEventEnvelope {
    let time = entry.time();
    OpenSetEventEnvelope {
        sequence: entry.sequence(),
        at: OpenSetEventTime {
            virtual_time_ticks: time.virtual_time.ticks,
            icount_retired: time.icount.icount.retired,
            icount_node: time.icount.node.as_ref().map(|node| node.name.clone()),
        },
        source: open_set_event_source(entry.source()),
        level: entry.level(),
        observational: entry.class() == SchedulerEventLogClass::Observational,
        payload: open_set_payload_from_event_payload(entry.event_payload()),
    }
}

/// Event payload received by a client.
#[derive(Clone, Debug, PartialEq)]
pub enum ReceivedOpenSetEventPayload {
    /// Payload kind is known in the current event-log catalog.
    Known(OpenSetPayload),
    /// Payload kind is unknown and must be carried opaquely.
    Opaque(OpenSetPayload),
}

impl ReceivedOpenSetEventPayload {
    /// Returns the carried open-set payload.
    #[must_use]
    pub const fn payload(&self) -> &OpenSetPayload {
        match self {
            Self::Known(payload) | Self::Opaque(payload) => payload,
        }
    }

    /// Returns whether this payload was unknown to the current client.
    #[must_use]
    pub const fn is_opaque(&self) -> bool {
        matches!(self, Self::Opaque(_))
    }
}

/// Classifies a received event payload without rejecting unknown event kinds.
#[must_use]
pub fn receive_open_set_event_payload(payload: OpenSetPayload) -> ReceivedOpenSetEventPayload {
    match catalog_event_kind_from_wire(&payload.kind) {
        Some(kind) if event_kind_catalog_entry(kind).is_some() => {
            ReceivedOpenSetEventPayload::Known(payload)
        }
        Some(_) | None => ReceivedOpenSetEventPayload::Opaque(payload),
    }
}

/// Error returned when validating an open-set payload being sent to the server.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum OpenSetPayloadError {
    /// The payload kind is not advertised in the category's capability set.
    #[error("{category} payload kind `{kind}` is not supported")]
    UnsupportedKind {
        /// Category in which the kind was looked up.
        category: OpenSetPayloadCategory,
        /// Unsupported kind string.
        kind: String,
    },
    /// A supported kind carried malformed arguments.
    #[error("{category} payload `{kind}` has invalid argument `{argument}`: {reason}")]
    InvalidArgument {
        /// Category in which validation failed.
        category: OpenSetPayloadCategory,
        /// Payload kind being validated.
        kind: String,
        /// Argument or field name that failed validation.
        argument: String,
        /// Human-readable validation reason.
        reason: String,
    },
}

/// Validates an open-set payload before sending it to the server.
///
/// Unknown command, fault, and breakpoint kinds are reported as
/// [`OpenSetPayloadError::UnsupportedKind`]. Known kinds with undeclared
/// attributes are reported as [`OpenSetPayloadError::InvalidArgument`].
///
/// # Errors
///
/// Returns [`OpenSetPayloadError`] when the kind is not advertised for
/// `category`, when the kind is not a dotted API kind, or when an attribute is
/// not declared by that kind's schema.
pub fn validate_open_set_send_payload(
    category: OpenSetPayloadCategory,
    payload: &OpenSetPayload,
) -> Result<(), OpenSetPayloadError> {
    let Some(local_kind) = payload.kind.strip_prefix(category.prefix()) else {
        return Err(OpenSetPayloadError::UnsupportedKind {
            category,
            kind: payload.kind.clone(),
        });
    };
    if local_kind.is_empty() {
        return Err(OpenSetPayloadError::InvalidArgument {
            category,
            kind: payload.kind.clone(),
            argument: String::from("kind"),
            reason: String::from("kind suffix is empty"),
        });
    }

    let capabilities = current_open_set_capabilities();
    let Some(schema) = capabilities.schema_for(category, &payload.kind) else {
        return Err(OpenSetPayloadError::UnsupportedKind {
            category,
            kind: payload.kind.clone(),
        });
    };

    for attribute in payload.attributes.keys() {
        if !schema.allows_attribute(attribute) {
            return Err(OpenSetPayloadError::InvalidArgument {
                category,
                kind: payload.kind.clone(),
                argument: attribute.clone(),
                reason: String::from("attribute is not declared for this kind"),
            });
        }
    }

    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct OpenSetKindTemplate {
    local_kind: &'static str,
    attributes: &'static [&'static str],
}

impl OpenSetKindTemplate {
    fn schema(self, category: OpenSetPayloadCategory) -> OpenSetKindSchema {
        OpenSetKindSchema {
            category,
            kind: open_set_kind(category, self.local_kind),
            attributes: self
                .attributes
                .iter()
                .map(|attribute| (*attribute).to_owned())
                .collect(),
        }
    }
}

const BREAKPOINT_KIND_TEMPLATES: &[OpenSetKindTemplate] = &[
    OpenSetKindTemplate {
        local_kind: "at",
        attributes: &["virtual_time_ticks", "predicate", "policy", "disposition"],
    },
    OpenSetKindTemplate {
        local_kind: "after",
        attributes: &[
            "duration_nanos",
            "event",
            "predicate",
            "policy",
            "disposition",
        ],
    },
    OpenSetKindTemplate {
        local_kind: "timer",
        attributes: &["timer", "predicate", "policy", "disposition"],
    },
    OpenSetKindTemplate {
        local_kind: "network-match",
        attributes: &[
            "link",
            "frame_predicate",
            "predicate",
            "policy",
            "disposition",
        ],
    },
    OpenSetKindTemplate {
        local_kind: "console-match",
        attributes: &["node", "regex", "predicate", "policy", "disposition"],
    },
    OpenSetKindTemplate {
        local_kind: "coverage-point",
        attributes: &["node", "point", "predicate", "policy", "disposition"],
    },
    OpenSetKindTemplate {
        local_kind: "memory-predicate",
        attributes: &[
            "node",
            "place",
            "cmp",
            "value",
            "predicate",
            "policy",
            "disposition",
        ],
    },
    OpenSetKindTemplate {
        local_kind: "io-pattern",
        attributes: &["node", "io_kind", "predicate", "policy", "disposition"],
    },
    OpenSetKindTemplate {
        local_kind: "node-state",
        attributes: &["node", "state", "predicate", "policy", "disposition"],
    },
    OpenSetKindTemplate {
        local_kind: "assertion-state",
        attributes: &["assertion", "state", "predicate", "policy", "disposition"],
    },
    OpenSetKindTemplate {
        local_kind: "quiescent",
        attributes: &["predicate", "policy", "disposition"],
    },
    OpenSetKindTemplate {
        local_kind: "fault-active",
        attributes: &["tag", "predicate", "policy", "disposition"],
    },
    OpenSetKindTemplate {
        local_kind: "named",
        attributes: &["name", "nodes", "predicate", "policy", "disposition"],
    },
    OpenSetKindTemplate {
        local_kind: "guest-marker",
        attributes: &["marker", "predicate", "policy", "disposition"],
    },
    OpenSetKindTemplate {
        local_kind: "all-of",
        attributes: &["predicates", "predicate", "policy", "disposition"],
    },
    OpenSetKindTemplate {
        local_kind: "any-of",
        attributes: &["predicates", "predicate", "policy", "disposition"],
    },
    OpenSetKindTemplate {
        local_kind: "once",
        attributes: &["inner", "predicate", "policy", "disposition"],
    },
    OpenSetKindTemplate {
        local_kind: "not",
        attributes: &["inner", "predicate", "policy", "disposition"],
    },
];

const FAULT_KIND_TEMPLATES: &[OpenSetKindTemplate] = &[
    OpenSetKindTemplate {
        local_kind: "network.partition",
        attributes: &["tag", "content_hash", "link", "direction"],
    },
    OpenSetKindTemplate {
        local_kind: "network.loss",
        attributes: &["tag", "content_hash", "link", "rate_basis_points"],
    },
    OpenSetKindTemplate {
        local_kind: "network.reorder",
        attributes: &["tag", "content_hash", "link", "window_nanos"],
    },
    OpenSetKindTemplate {
        local_kind: "network.duplicate",
        attributes: &[
            "tag",
            "content_hash",
            "link",
            "rate_basis_points",
            "gap_nanos",
        ],
    },
    OpenSetKindTemplate {
        local_kind: "network.corruption.bit-flip",
        attributes: &[
            "tag",
            "content_hash",
            "link",
            "rate_basis_points",
            "max_bits",
        ],
    },
    OpenSetKindTemplate {
        local_kind: "network.corruption.field-mutation",
        attributes: &["tag", "content_hash", "link", "rate_basis_points"],
    },
    OpenSetKindTemplate {
        local_kind: "network.corruption.truncation",
        attributes: &[
            "tag",
            "content_hash",
            "link",
            "rate_basis_points",
            "max_bytes",
        ],
    },
    OpenSetKindTemplate {
        local_kind: "network.bandwidth",
        attributes: &["tag", "content_hash", "link", "bits_per_second"],
    },
    OpenSetKindTemplate {
        local_kind: "network.latency-bump",
        attributes: &["tag", "content_hash", "link", "extra_nanos"],
    },
    OpenSetKindTemplate {
        local_kind: "node.crash",
        attributes: &["tag", "content_hash", "node", "restart"],
    },
    OpenSetKindTemplate {
        local_kind: "node.slow",
        attributes: &["tag", "content_hash", "node", "factor_basis_points"],
    },
    OpenSetKindTemplate {
        local_kind: "node.clock-skew",
        attributes: &["tag", "content_hash", "node", "offset_nanos"],
    },
    OpenSetKindTemplate {
        local_kind: "block.latency",
        attributes: &[
            "tag",
            "content_hash",
            "device",
            "extra_nanos",
            "jitter_nanos",
        ],
    },
    OpenSetKindTemplate {
        local_kind: "block.failure",
        attributes: &["tag", "content_hash", "device", "rate_basis_points", "mode"],
    },
    OpenSetKindTemplate {
        local_kind: "block.reorder",
        attributes: &["tag", "content_hash", "device", "window_nanos"],
    },
    OpenSetKindTemplate {
        local_kind: "block.duplicate",
        attributes: &[
            "tag",
            "content_hash",
            "device",
            "rate_basis_points",
            "gap_nanos",
        ],
    },
    OpenSetKindTemplate {
        local_kind: "block.corruption.bit-flip",
        attributes: &[
            "tag",
            "content_hash",
            "device",
            "rate_basis_points",
            "bit_flips",
        ],
    },
    OpenSetKindTemplate {
        local_kind: "block.bandwidth",
        attributes: &["tag", "content_hash", "device", "bits_per_second"],
    },
    OpenSetKindTemplate {
        local_kind: "9p.latency",
        attributes: &[
            "tag",
            "content_hash",
            "device",
            "extra_nanos",
            "jitter_nanos",
        ],
    },
    OpenSetKindTemplate {
        local_kind: "9p.failure",
        attributes: &[
            "tag",
            "content_hash",
            "device",
            "rate_basis_points",
            "errno",
        ],
    },
    OpenSetKindTemplate {
        local_kind: "9p.reorder",
        attributes: &["tag", "content_hash", "device", "window_nanos"],
    },
    OpenSetKindTemplate {
        local_kind: "9p.duplicate",
        attributes: &[
            "tag",
            "content_hash",
            "device",
            "rate_basis_points",
            "gap_nanos",
        ],
    },
    OpenSetKindTemplate {
        local_kind: "9p.corruption.bit-flip",
        attributes: &[
            "tag",
            "content_hash",
            "device",
            "rate_basis_points",
            "bit_flips",
        ],
    },
    OpenSetKindTemplate {
        local_kind: "9p.bandwidth",
        attributes: &["tag", "content_hash", "device", "bits_per_second"],
    },
];

fn open_set_kind(category: OpenSetPayloadCategory, local_kind: &str) -> String {
    format!("{}{local_kind}", category.prefix())
}

fn command_schema(command_name: &str) -> OpenSetKindSchema {
    OpenSetKindSchema {
        category: OpenSetPayloadCategory::Command,
        kind: open_set_kind(OpenSetPayloadCategory::Command, command_name),
        attributes: command_attributes(command_name)
            .iter()
            .map(|attribute| (*attribute).to_owned())
            .collect(),
    }
}

fn command_attributes(command_name: &str) -> &'static [&'static str] {
    match command_name {
        "start" | "continue" | "pause" | "step-quantum" | "step-event" | "step-assertion"
        | "step-timer" | "stop" | "exhaust-budget" | "inject" | "snapshot" => &[],
        "step-duration" => &["duration_nanos"],
        "inject-fault" => &["tag", "fault_kind", "fault"],
        "heal-fault" => &["tag"],
        "set-breakpoint" => &["predicate_kind", "predicate", "policy", "disposition"],
        "remove-breakpoint" => &["id"],
        "create-savepoint" => &["label"],
        "fork" => &["from"],
        "query" => &["query"],
        "attach-gdb" => &["node", "listen"],
        "debug-goto" => &["target"],
        "debug-reverse-step" => &["grain"],
        "debug-reverse-continue" => &["predicate_kind", "predicate"],
        "debug-fork-non-canonical" => &["evidence"],
        _ => &["extension"],
    }
}

fn catalog_event_kind_from_wire(kind: &str) -> Option<&str> {
    kind.strip_prefix(OPEN_SET_EVENT_KIND_PREFIX)
        .filter(|local_kind| !local_kind.is_empty())
}

fn open_set_event_source(source: &EventSource) -> OpenSetEventSource {
    match source {
        EventSource::Scenario { event } => OpenSetEventSource::Scenario {
            event: event.name.clone(),
        },
        EventSource::Engine => OpenSetEventSource::Engine,
        EventSource::Node { node } => OpenSetEventSource::Node {
            node: node.name.clone(),
        },
        EventSource::Guest { node } => OpenSetEventSource::Guest {
            node: node.name.clone(),
        },
        EventSource::Command { command_id } => OpenSetEventSource::Command {
            command_id: *command_id,
        },
    }
}

fn event_level_label(level: EventLevel) -> &'static str {
    match level {
        EventLevel::Trace => "trace",
        EventLevel::Debug => "debug",
        EventLevel::Info => "info",
        EventLevel::Warn => "warn",
        EventLevel::Error => "error",
    }
}

fn breakpoint_policy_label(policy: BreakpointPolicy) -> &'static str {
    match policy {
        BreakpointPolicy::OneShot => "one-shot",
        BreakpointPolicy::Repeatable => "repeatable",
    }
}

fn breakpoint_disposition_label(disposition: &BreakpointDisposition) -> &'static str {
    match disposition {
        BreakpointDisposition::Suspend => "suspend",
        BreakpointDisposition::Trace => "trace",
        BreakpointDisposition::Action(_) => "action",
    }
}
