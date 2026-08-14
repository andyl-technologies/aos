//! Immutable scenario-definition identity and constructors.

use super::*;

/// A handle to an immutable scenario definition.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ScenarioDef {
    /// The content address of the scenario definition.
    pub(super) id: ContentHash,
    /// The root entropy carried by this scenario definition.
    pub(super) seed: Seed,
    /// The maximum number of app-random decisions admitted for one run.
    pub(super) app_random_draw_cap: u64,
}

impl ScenarioDef {
    /// Returns the content address of this scenario definition.
    #[must_use]
    pub fn id(&self) -> ContentHash {
        self.id
    }

    /// Returns the root entropy carried by this scenario definition.
    #[must_use]
    pub fn seed(&self) -> Seed {
        self.seed
    }

    /// Returns the configured app-random draw cap for this scenario.
    #[must_use]
    pub fn app_random_draw_cap(&self) -> u64 {
        self.app_random_draw_cap
    }

    /// Rebuilds a scenario definition handle from trusted content-addressed identity fields.
    ///
    /// This is a transport and artifact decoding helper for cases that already
    /// received a validated scenario definition elsewhere and only need to
    /// rehydrate the identity-bearing execution handle. Scenario authors should
    /// use [`ScenarioDefForm`] or the builder APIs instead so component hashes
    /// are derived from canonical scenario content.
    #[must_use]
    pub const fn from_trusted_identity(
        id: ContentHash,
        seed: Seed,
        app_random_draw_cap: u64,
    ) -> Self {
        Self {
            id,
            seed,
            app_random_draw_cap,
        }
    }

    /// Builds a scenario definition from canonical material.
    ///
    /// This helper is the engine-side content-addressing entry point for
    /// backend-produced canonical material.
    #[must_use]
    pub fn from_canonical_material(domain: &str, material: &str) -> Self {
        Self::from_canonical_material_with_seed(domain, material, Seed::default())
    }

    /// Builds a scenario definition from canonical material and root seed.
    ///
    /// This helper is the compatibility entry point for backend-produced
    /// canonical material when the caller also has the scenario seed component.
    /// The seed is included in the returned content address so it cannot drift
    /// from scenario identity.
    #[must_use]
    pub fn from_canonical_material_with_seed(domain: &str, material: &str, seed: Seed) -> Self {
        Self::from_canonical_material_with_seed_and_app_random_draw_cap(
            domain,
            material,
            seed,
            DEFAULT_APP_RANDOM_DRAW_CAP,
        )
    }

    /// Builds a scenario definition from canonical material, root seed, and
    /// app-random draw cap.
    ///
    /// The cap is included in the returned content address so app-random policy
    /// cannot drift from scenario identity.
    #[must_use]
    pub fn from_canonical_material_with_seed_and_app_random_draw_cap(
        domain: &str,
        material: &str,
        seed: Seed,
        app_random_draw_cap: u64,
    ) -> Self {
        let material = format!(
            "{material}\n{}\n{}",
            seed_material(seed),
            app_random_draw_cap_material(app_random_draw_cap)
        );
        Self {
            id: ContentHash::from_canonical_material(domain, &material),
            seed,
            app_random_draw_cap,
        }
    }

    /// Builds an opaque scenario definition from already-addressed components.
    ///
    /// This is the compatibility path for API adapters that receive an inline
    /// scenario handle over a transport before the full scenario form lands on
    /// the wire. Callers are responsible for supplying the content address that
    /// corresponds to the seed and app-random policy.
    #[must_use]
    pub fn from_content_hash_seed_and_app_random_draw_cap(
        id: ContentHash,
        seed: Seed,
        app_random_draw_cap: u64,
    ) -> Self {
        Self {
            id,
            seed,
            app_random_draw_cap,
        }
    }
}
