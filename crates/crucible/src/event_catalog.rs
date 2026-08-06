//! Versioned event-kind catalog for scheduler event-log payloads.
//!
//! The catalog is the single class source for open-set event payload kinds. It is
//! intentionally data-shaped: consumers can discover the current version, the
//! known kind strings, each kind's fixed [`SchedulerEventLogClass`], the stable
//! typed attributes, and the RFC surfaces that structurally depend on those
//! kinds.

use crate::scheduler::SchedulerEventLogClass;

/// Current event-kind catalog schema version.
pub const EVENT_KIND_CATALOG_VERSION: u32 = 2;

/// One open-set event kind known by this engine version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EventKindCatalogEntry {
    kind: &'static str,
    class: SchedulerEventLogClass,
    sources: &'static [&'static str],
    attributes: &'static [&'static str],
}

impl EventKindCatalogEntry {
    /// Returns the stable open-set kind string.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        self.kind
    }

    /// Returns the fixed event-log class for this kind.
    #[must_use]
    pub const fn class(&self) -> SchedulerEventLogClass {
        self.class
    }

    /// Returns the allowed source families for this kind.
    #[must_use]
    pub const fn sources(&self) -> &'static [&'static str] {
        self.sources
    }

    /// Returns the stable typed attribute names for this kind.
    #[must_use]
    pub const fn attributes(&self) -> &'static [&'static str] {
        self.attributes
    }

    /// Returns this entry's canonical catalog line.
    #[must_use]
    pub fn canonical_line(&self) -> String {
        format!(
            "entry kind={} class={} sources={} attributes={}",
            self.kind,
            event_kind_catalog_class_label(self.class),
            self.sources.join(","),
            self.attributes.join(","),
        )
    }

    /// Returns this entry's canonical byte serialization.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        self.canonical_line().into_bytes()
    }
}

/// One RFC consumer and the catalog kinds it depends on structurally.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EventKindCatalogDependency {
    consumer: &'static str,
    kinds: &'static [&'static str],
}

impl EventKindCatalogDependency {
    /// Returns the RFC file or surface that consumes catalog kinds.
    #[must_use]
    pub const fn consumer(&self) -> &'static str {
        self.consumer
    }

    /// Returns the catalog kinds this consumer reads, or `*` for the full catalog.
    #[must_use]
    pub const fn kinds(&self) -> &'static [&'static str] {
        self.kinds
    }

    /// Returns this dependency's canonical catalog line.
    #[must_use]
    pub fn canonical_line(&self) -> String {
        format!(
            "dependency consumer={} kinds={}",
            self.consumer,
            self.kinds.join(",")
        )
    }
}

const FAULT_OBSERVATION_ATTRIBUTES: &[&str] = &[
    "binding",
    "coordinate",
    "evidence",
    "opportunity",
    "retired_instructions",
    "semantic_version",
    "target",
    "target_kind",
];

static EVENT_KIND_CATALOG: &[EventKindCatalogEntry] = &[
    EventKindCatalogEntry {
        kind: "app_random",
        class: SchedulerEventLogClass::Causal,
        sources: &["guest", "node"],
        attributes: &[
            "node",
            "request_id",
            "stream_domain",
            "stream_name",
            "value",
            "width",
        ],
    },
    EventKindCatalogEntry {
        kind: "assertion_evaluated",
        class: SchedulerEventLogClass::Causal,
        sources: &["engine", "guest"],
        attributes: &[
            "condition",
            "detail.*.key",
            "detail.*.value",
            "details_len",
            "flavor",
            "id",
            "message",
        ],
    },
    EventKindCatalogEntry {
        kind: "assertion_proximity",
        class: SchedulerEventLogClass::Observational,
        sources: &["engine"],
        attributes: &["distance", "id", "node", "quantifier"],
    },
    EventKindCatalogEntry {
        kind: "assertion_state_changed",
        class: SchedulerEventLogClass::Causal,
        sources: &["engine"],
        attributes: &["id", "new_state"],
    },
    EventKindCatalogEntry {
        kind: "association_transition",
        class: SchedulerEventLogClass::Causal,
        sources: &["engine"],
        attributes: FAULT_OBSERVATION_ATTRIBUTES,
    },
    EventKindCatalogEntry {
        kind: "backend_input",
        class: SchedulerEventLogClass::Causal,
        sources: &["engine", "node"],
        attributes: &[
            "consumer",
            "node",
            "payload",
            "producer",
            "sequence",
            "virtual_time",
        ],
    },
    EventKindCatalogEntry {
        kind: "binding_activation",
        class: SchedulerEventLogClass::Causal,
        sources: &["engine"],
        attributes: FAULT_OBSERVATION_ATTRIBUTES,
    },
    EventKindCatalogEntry {
        kind: "binding_deactivation",
        class: SchedulerEventLogClass::Causal,
        sources: &["engine"],
        attributes: FAULT_OBSERVATION_ATTRIBUTES,
    },
    EventKindCatalogEntry {
        kind: "console_output",
        class: SchedulerEventLogClass::Observational,
        sources: &["node"],
        attributes: &["bytes", "node"],
    },
    EventKindCatalogEntry {
        kind: "control",
        class: SchedulerEventLogClass::Causal,
        sources: &["command"],
        attributes: &[
            "command",
            "command_id",
            "consumer",
            "producer",
            "sequence",
            "virtual_time",
        ],
    },
    EventKindCatalogEntry {
        kind: "coverage",
        class: SchedulerEventLogClass::Observational,
        sources: &["engine", "guest"],
        attributes: &[
            "block",
            "block_len",
            "execution_icount",
            "guest_pc",
            "id",
            "kind",
            "node",
            "retired_icount",
        ],
    },
    EventKindCatalogEntry {
        kind: "delivery_order",
        class: SchedulerEventLogClass::Causal,
        sources: &["engine"],
        attributes: &["at", "events"],
    },
    EventKindCatalogEntry {
        kind: "diagnostic",
        class: SchedulerEventLogClass::Observational,
        sources: &["command", "engine", "node"],
        attributes: &["details", "name"],
    },
    EventKindCatalogEntry {
        kind: "effect_applied",
        class: SchedulerEventLogClass::Causal,
        sources: &["engine"],
        attributes: FAULT_OBSERVATION_ATTRIBUTES,
    },
    EventKindCatalogEntry {
        kind: "effect_combined",
        class: SchedulerEventLogClass::Causal,
        sources: &["engine"],
        attributes: FAULT_OBSERVATION_ATTRIBUTES,
    },
    EventKindCatalogEntry {
        kind: "effect_rejected",
        class: SchedulerEventLogClass::Causal,
        sources: &["engine"],
        attributes: FAULT_OBSERVATION_ATTRIBUTES,
    },
    EventKindCatalogEntry {
        kind: "evaluation_boundary",
        class: SchedulerEventLogClass::Causal,
        sources: &["engine"],
        attributes: &["boundary"],
    },
    EventKindCatalogEntry {
        kind: "event_activated",
        class: SchedulerEventLogClass::Causal,
        sources: &["scenario"],
        attributes: &["event", "summary"],
    },
    EventKindCatalogEntry {
        kind: "fault_activated",
        class: SchedulerEventLogClass::Causal,
        sources: &["engine", "scenario"],
        attributes: &["description", "kind", "tag", "targets"],
    },
    EventKindCatalogEntry {
        kind: "fault_activation",
        class: SchedulerEventLogClass::Causal,
        sources: &["engine", "scenario"],
        attributes: &["consumer", "fault", "producer", "sequence", "virtual_time"],
    },
    EventKindCatalogEntry {
        kind: "fault_choice",
        class: SchedulerEventLogClass::Causal,
        sources: &["engine"],
        attributes: FAULT_OBSERVATION_ATTRIBUTES,
    },
    EventKindCatalogEntry {
        kind: "fault_fires",
        class: SchedulerEventLogClass::Causal,
        sources: &["engine"],
        attributes: &["at", "fault", "fired"],
    },
    EventKindCatalogEntry {
        kind: "fault_healed",
        class: SchedulerEventLogClass::Causal,
        sources: &["engine", "scenario"],
        attributes: &["tag"],
    },
    EventKindCatalogEntry {
        kind: "fault_opportunity",
        class: SchedulerEventLogClass::Causal,
        sources: &["engine"],
        attributes: FAULT_OBSERVATION_ATTRIBUTES,
    },
    EventKindCatalogEntry {
        kind: "fork",
        class: SchedulerEventLogClass::Causal,
        sources: &["command", "engine"],
        attributes: &["from_checkpoint_id", "schedule_delta"],
    },
    EventKindCatalogEntry {
        kind: "guest_marker",
        class: SchedulerEventLogClass::Observational,
        sources: &["guest"],
        attributes: &[
            "assertion",
            "condition",
            "detail.*.key",
            "detail.*.value",
            "details_len",
            "flavor",
            "location",
            "marker",
            "marker_kind",
            "message",
            "must_hit",
            "node",
            "retired_icount",
        ],
    },
    EventKindCatalogEntry {
        kind: "io_completion",
        class: SchedulerEventLogClass::Causal,
        sources: &["engine", "node"],
        attributes: &[
            "consumer",
            "delivery_icount",
            "node",
            "payload",
            "producer",
            "sequence",
            "virtual_time",
        ],
    },
    EventKindCatalogEntry {
        kind: "memory_sample",
        class: SchedulerEventLogClass::Observational,
        sources: &["engine", "node"],
        attributes: &["node", "place", "sample_icount", "value"],
    },
    EventKindCatalogEntry {
        kind: "message_delivered",
        class: SchedulerEventLogClass::Causal,
        sources: &["engine", "node"],
        attributes: &["deliver_icount", "from", "len", "link", "seq", "to"],
    },
    EventKindCatalogEntry {
        kind: "message_dropped",
        class: SchedulerEventLogClass::Causal,
        sources: &["engine", "node"],
        attributes: &["from", "link", "reason", "to"],
    },
    EventKindCatalogEntry {
        kind: "network_delivered",
        class: SchedulerEventLogClass::Observational,
        sources: &["engine", "node"],
        attributes: &["link", "payload"],
    },
    EventKindCatalogEntry {
        kind: "network_profile",
        class: SchedulerEventLogClass::Causal,
        sources: &["engine"],
        attributes: FAULT_OBSERVATION_ATTRIBUTES,
    },
    EventKindCatalogEntry {
        kind: "node_completed",
        class: SchedulerEventLogClass::Causal,
        sources: &["engine", "node"],
        attributes: &["node", "outcome"],
    },
    EventKindCatalogEntry {
        kind: "node_crashed",
        class: SchedulerEventLogClass::Causal,
        sources: &["engine", "node"],
        attributes: &["node", "reason"],
    },
    EventKindCatalogEntry {
        kind: "node_started",
        class: SchedulerEventLogClass::Causal,
        sources: &["engine", "node"],
        attributes: &["node", "ready_point"],
    },
    EventKindCatalogEntry {
        kind: "node_state",
        class: SchedulerEventLogClass::Observational,
        sources: &["engine", "node"],
        attributes: &["node", "state"],
    },
    EventKindCatalogEntry {
        kind: "observed_io_completion",
        class: SchedulerEventLogClass::Observational,
        sources: &["engine", "node"],
        attributes: &["kind", "node", "payload"],
    },
    EventKindCatalogEntry {
        kind: "override",
        class: SchedulerEventLogClass::Causal,
        sources: &["engine"],
        attributes: &["choice", "point"],
    },
    EventKindCatalogEntry {
        kind: "preemption",
        class: SchedulerEventLogClass::Causal,
        sources: &["engine"],
        attributes: &["at", "kind", "node"],
    },
    EventKindCatalogEntry {
        kind: "probabilistic_fault",
        class: SchedulerEventLogClass::Causal,
        sources: &["engine"],
        attributes: &[
            "consumer",
            "fault",
            "producer",
            "rate_basis_points",
            "sequence",
            "stream_domain",
            "stream_name",
            "virtual_time",
        ],
    },
    EventKindCatalogEntry {
        kind: "rng_draw",
        class: SchedulerEventLogClass::Causal,
        sources: &["engine"],
        attributes: &["stream_domain", "stream_name", "value"],
    },
    EventKindCatalogEntry {
        kind: "savepoint",
        class: SchedulerEventLogClass::Causal,
        sources: &["command", "engine"],
        attributes: &["checkpoint_id", "event_log_offset"],
    },
    EventKindCatalogEntry {
        kind: "signal_sample",
        class: SchedulerEventLogClass::Causal,
        sources: &["engine"],
        attributes: FAULT_OBSERVATION_ATTRIBUTES,
    },
    EventKindCatalogEntry {
        kind: "signal_state_transition",
        class: SchedulerEventLogClass::Causal,
        sources: &["engine"],
        attributes: FAULT_OBSERVATION_ATTRIBUTES,
    },
    EventKindCatalogEntry {
        kind: "signal_transition",
        class: SchedulerEventLogClass::Causal,
        sources: &["engine"],
        attributes: FAULT_OBSERVATION_ATTRIBUTES,
    },
    EventKindCatalogEntry {
        kind: "state_transition",
        class: SchedulerEventLogClass::Causal,
        sources: &["engine", "node"],
        attributes: &["cause", "from_state", "node", "to_state"],
    },
    EventKindCatalogEntry {
        kind: "tick",
        class: SchedulerEventLogClass::Causal,
        sources: &["engine"],
        attributes: &["icount", "virtual_time"],
    },
    EventKindCatalogEntry {
        kind: "timer_armed",
        class: SchedulerEventLogClass::Causal,
        sources: &["engine", "node"],
        attributes: &["fire_icount", "node", "timer"],
    },
    EventKindCatalogEntry {
        kind: "timer_cancelled",
        class: SchedulerEventLogClass::Causal,
        sources: &["engine", "node"],
        attributes: &["node", "timer"],
    },
    EventKindCatalogEntry {
        kind: "timer_fired",
        class: SchedulerEventLogClass::Causal,
        sources: &["engine", "node"],
        attributes: &["node", "timer"],
    },
    EventKindCatalogEntry {
        kind: "trace_alignment",
        class: SchedulerEventLogClass::Causal,
        sources: &["engine"],
        attributes: FAULT_OBSERVATION_ATTRIBUTES,
    },
    EventKindCatalogEntry {
        kind: "trigger_action_applied",
        class: SchedulerEventLogClass::Causal,
        sources: &["engine", "scenario"],
        attributes: &["action", "at", "event", "sequence"],
    },
    EventKindCatalogEntry {
        kind: "trigger_fired",
        class: SchedulerEventLogClass::Causal,
        sources: &["engine", "scenario"],
        attributes: &["action", "at", "condition", "event"],
    },
];

static EVENT_KIND_CATALOG_DEPENDENCIES: &[EventKindCatalogDependency] = &[
    EventKindCatalogDependency {
        consumer: "0012-05-recording-replay-observability",
        kinds: &[
            "association_transition",
            "binding_activation",
            "binding_deactivation",
            "effect_applied",
            "effect_combined",
            "effect_rejected",
            "fault_choice",
            "fault_opportunity",
            "network_profile",
            "signal_sample",
            "signal_state_transition",
            "signal_transition",
            "trace_alignment",
        ],
    },
    EventKindCatalogDependency {
        consumer: "18-assertions-properties",
        kinds: &[
            "assertion_evaluated",
            "assertion_proximity",
            "assertion_state_changed",
            "guest_marker",
        ],
    },
    EventKindCatalogDependency {
        consumer: "20-session-control-plane",
        kinds: &["*"],
    },
    EventKindCatalogDependency {
        consumer: "21-api",
        kinds: &["*"],
    },
    EventKindCatalogDependency {
        consumer: "22-advanced-features",
        kinds: &["assertion_proximity", "coverage"],
    },
    EventKindCatalogDependency {
        consumer: "24-determinism-harness-testing",
        kinds: &[
            "app_random",
            "assertion_evaluated",
            "assertion_state_changed",
            "association_transition",
            "backend_input",
            "binding_activation",
            "binding_deactivation",
            "control",
            "delivery_order",
            "effect_applied",
            "effect_combined",
            "effect_rejected",
            "evaluation_boundary",
            "event_activated",
            "fault_activated",
            "fault_activation",
            "fault_choice",
            "fault_fires",
            "fault_healed",
            "fault_opportunity",
            "fork",
            "io_completion",
            "message_delivered",
            "message_dropped",
            "network_profile",
            "node_completed",
            "node_crashed",
            "node_started",
            "override",
            "preemption",
            "probabilistic_fault",
            "rng_draw",
            "savepoint",
            "signal_sample",
            "signal_state_transition",
            "signal_transition",
            "state_transition",
            "tick",
            "timer_armed",
            "timer_cancelled",
            "timer_fired",
            "trace_alignment",
            "trigger_action_applied",
            "trigger_fired",
        ],
    },
];

/// Returns the current versioned event-kind catalog.
#[must_use]
pub fn event_kind_catalog() -> &'static [EventKindCatalogEntry] {
    EVENT_KIND_CATALOG
}

/// Returns the catalog entry for `kind`.
#[must_use]
pub fn event_kind_catalog_entry(kind: &str) -> Option<&'static EventKindCatalogEntry> {
    EVENT_KIND_CATALOG.iter().find(|entry| entry.kind == kind)
}

/// Returns the fixed class for `kind`.
#[must_use]
pub fn event_kind_catalog_class(kind: &str) -> Option<SchedulerEventLogClass> {
    event_kind_catalog_entry(kind).map(EventKindCatalogEntry::class)
}

/// Returns the structural RFC dependency map for catalog consumers.
#[must_use]
pub fn event_kind_catalog_dependency_map() -> &'static [EventKindCatalogDependency] {
    EVENT_KIND_CATALOG_DEPENDENCIES
}

/// Returns the canonical text material for the current catalog.
#[must_use]
pub fn event_kind_catalog_canonical_material() -> String {
    let mut lines = Vec::new();
    lines.push(format!(
        "event_kind_catalog.version={EVENT_KIND_CATALOG_VERSION}"
    ));
    lines.push(format!(
        "event_kind_catalog.entries={}",
        EVENT_KIND_CATALOG.len()
    ));
    for entry in EVENT_KIND_CATALOG {
        lines.push(entry.canonical_line());
    }
    lines.push(format!(
        "event_kind_catalog.dependencies={}",
        EVENT_KIND_CATALOG_DEPENDENCIES.len()
    ));
    for dependency in EVENT_KIND_CATALOG_DEPENDENCIES {
        lines.push(dependency.canonical_line());
    }
    lines.join("\n")
}

/// Returns the canonical byte serialization for the current catalog.
#[must_use]
pub fn event_kind_catalog_canonical_bytes() -> Vec<u8> {
    event_kind_catalog_canonical_material().into_bytes()
}

fn event_kind_catalog_class_label(class: SchedulerEventLogClass) -> &'static str {
    match class {
        SchedulerEventLogClass::Causal => "causal",
        SchedulerEventLogClass::Observational => "observational",
    }
}
