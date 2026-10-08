//! Sealed gate for dormant publisher physical effects.
//!
//! Physical preparation and completion retain this opaque borrowed gate. No
//! constructor produces it, so those implementations remain unavailable until
//! a qualified authority producer exists. Opening the fixed publisher owner
//! claims only the domain service.

/// Proves explicit activation of the dormant publisher's physical effects.
///
/// This move-only capability has no constructor. The fixed production
/// owner returns only the domain service, so possessing the service, an
/// authenticated execution, source descriptor, and root custody still does
/// not authorize inode materialization, fs-verity enablement, or publication.
#[must_use = "a dormant publisher effect capability must remain explicitly retained"]
pub struct PublisherDormantEffectCapabilityV1<'activation> {
    _activation: &'activation mut PublisherDormantEffectActivationSealV1,
}

struct PublisherDormantEffectActivationSealV1 {
    #[allow(
        dead_code,
        reason = "the physical-effect gate has no authority producer"
    )]
    private: (),
}
