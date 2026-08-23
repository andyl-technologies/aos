//! Versioned event-kind catalog for scheduler event-log payloads.
//!
//! The catalog is the single class source for open-set event payload kinds. It is
//! intentionally data-shaped: consumers can discover the current version, the
//! known kind strings, each kind's fixed [`SchedulerEventLogClass`], the stable
//! typed attributes, and the RFC surfaces that structurally depend on those
//! kinds.

use crate::scheduler::SchedulerEventLogClass;

/// Current event-kind catalog schema version.
pub const EVENT_KIND_CATALOG_VERSION: u32 = 6;

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

mod catalog;

use catalog::*;

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
