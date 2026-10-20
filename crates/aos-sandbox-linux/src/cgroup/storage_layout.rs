//! Closed Storage cgroup coordinates, without profile or service admission.
//!
//! Callers select these DATA recipes only from their existing genuine admitted
//! profile/unit evidence. Neither enum value creates an original or permits a
//! fallback after failure of a selected fixed recipe.

/// Names the two supported fixed Storage containment layouts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageCgroupLayoutV1 {
    /// Preserves the ordinary main and helper locations.
    Ordinary,
    /// Places the fixed main/helper roster beneath the same paid aggregate.
    ReceivingAggregate,
}

impl StorageCgroupLayoutV1 {
    /// Returns the fixed main path relative to the cgroup-v2 hierarchy.
    #[must_use]
    pub const fn main_relative_v1(self) -> &'static str {
        match self {
            Self::Ordinary => "aos.slice/aos-control.slice/aos-storaged.service",
            Self::ReceivingAggregate => "aos.slice/aos-control.slice/aos-control-storage.slice/aos-storaged.service",
        }
    }

    /// Returns the same main coordinate in PID1's absolute ControlGroup form.
    #[must_use]
    pub const fn main_control_group_v1(self) -> &'static str {
        match self {
            Self::Ordinary => "/aos.slice/aos-control.slice/aos-storaged.service",
            Self::ReceivingAggregate => "/aos.slice/aos-control.slice/aos-control-storage.slice/aos-storaged.service",
        }
    }

    /// Returns the fixed directory enclosing that layout's closed helper roster.
    #[must_use]
    pub const fn worker_parent_relative_v1(self) -> &'static str {
        match self {
            Self::Ordinary => "aos.slice/aos-control.slice",
            Self::ReceivingAggregate => "aos.slice/aos-control.slice/aos-control-storage.slice",
        }
    }
}
