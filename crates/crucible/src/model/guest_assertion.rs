//! Canonical declarations for assertions evaluated inside a guest.

use super::{
    AssertionDef, AssertionId, MarkerId, Predicate, Property, ReachabilityExpectation,
    ReachableDisposition,
};

impl AssertionDef {
    /// Declares a guest-side `always` assertion sourced from the white-box channel.
    #[must_use]
    pub fn guest_always(id: AssertionId, message: impl Into<String>) -> Self {
        let marker = MarkerId::from_name(id.name.clone());
        Self {
            id,
            message: message.into(),
            property: Property::Always {
                predicate: Predicate::guest_marker(marker),
            },
        }
    }

    /// Declares a guest-side `sometimes` assertion sourced from the white-box channel.
    ///
    /// The returned property is encoded with the existing shared `GuestMarker`
    /// predicate vocabulary, using the assertion id as the marker id. The host
    /// assertion evaluator recognizes this canonical shape as a catalog declaration
    /// and evaluates assertion-flavored doorbell markers instead of bare marker
    /// events.
    #[must_use]
    pub fn guest_sometimes(id: AssertionId, message: impl Into<String>) -> Self {
        let marker = MarkerId::from_name(id.name.clone());
        Self {
            id,
            message: message.into(),
            property: Property::Sometimes {
                predicate: Predicate::guest_marker(marker),
            },
        }
    }

    /// Declares a guest-side reachable assertion sourced from the white-box channel.
    #[must_use]
    pub fn guest_reachable(
        id: AssertionId,
        message: impl Into<String>,
        on_unreached: ReachableDisposition,
    ) -> Self {
        let marker = MarkerId::from_name(id.name.clone());
        Self {
            id,
            message: message.into(),
            property: Property::Reachable {
                predicate: Predicate::guest_marker(marker),
                expectation: ReachabilityExpectation::Reachable { on_unreached },
            },
        }
    }

    /// Declares a guest-side unreachable assertion sourced from the white-box channel.
    #[must_use]
    pub fn guest_unreachable(id: AssertionId, message: impl Into<String>) -> Self {
        let marker = MarkerId::from_name(id.name.clone());
        Self {
            id,
            message: message.into(),
            property: Property::Reachable {
                predicate: Predicate::guest_marker(marker),
                expectation: ReachabilityExpectation::Unreachable,
            },
        }
    }
}
