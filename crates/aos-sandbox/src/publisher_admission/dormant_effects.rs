//! Explicit non-production composition for dormant publisher effects.
//!
//! The fixed publisher owner and every public production constructor omit this
//! composition. A crate-internal integration must deliberately mint sealed
//! injection provenance, consume it into the composition, and retain the
//! resulting borrow while dispatching physical publisher effects. This module
//! registers no listener, route, service, unit, or automatic activation path.

/// Records an explicit caller decision to inject dormant publisher effects.
///
/// The value is move-only and crate-sealed. It is available in normal source so
/// a non-production integration can exercise the complete physical path, but
/// it cannot enter through the public fixed-owner construction boundary.
#[must_use = "dormant effect provenance must be consumed by an injected composition"]
pub(crate) struct PublisherDormantEffectProvenanceV1 {
    private: (),
}

impl PublisherDormantEffectProvenanceV1 {
    /// Seals one deliberate crate-internal dormant-effect injection decision.
    #[must_use]
    pub(crate) const fn for_non_production_injection() -> Self {
        Self { private: () }
    }
}

/// Retains caller-supplied provenance for a dormant publisher composition.
///
/// Construction is crate-private and requires the separate sealed provenance
/// value. Merely opening or claiming the fixed publisher owner does not create
/// this composition.
#[must_use = "an injected dormant composition must retain its effect activation"]
pub(crate) struct PublisherDormantEffectCompositionV1 {
    _provenance: PublisherDormantEffectProvenanceV1,
    activation: PublisherDormantEffectActivationSealV1,
}

impl PublisherDormantEffectCompositionV1 {
    /// Consumes explicit provenance into one dormant effect composition.
    #[must_use]
    pub(crate) const fn inject(provenance: PublisherDormantEffectProvenanceV1) -> Self {
        let _ = provenance.private;
        Self {
            _provenance: provenance,
            activation: PublisherDormantEffectActivationSealV1 { private: () },
        }
    }

    /// Borrows the composition as physical publisher-effect authority.
    pub(crate) fn activate(&mut self) -> PublisherDormantEffectCapabilityV1<'_> {
        let _ = self.activation.private;
        PublisherDormantEffectCapabilityV1 {
            _activation: &mut self.activation,
        }
    }
}

/// Proves explicit activation of the dormant publisher's physical effects.
///
/// This move-only capability has no public constructor. The fixed production
/// owner returns only the domain service, so possessing the service, an
/// authenticated execution, source descriptor, and root custody still does
/// not authorize inode materialization, fs-verity enablement, or publication.
#[must_use = "a dormant publisher effect capability must remain explicitly retained"]
pub struct PublisherDormantEffectCapabilityV1<'activation> {
    _activation: &'activation mut PublisherDormantEffectActivationSealV1,
}

struct PublisherDormantEffectActivationSealV1 {
    private: (),
}
