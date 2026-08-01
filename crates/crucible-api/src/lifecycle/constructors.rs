//! Lifecycle control-plane constructors and production loop-factory admission.

use super::*;

impl<L> LifecycleControlPlane<L, LifecycleLoopFactory<L>>
where
    L: QuantumLoop + Send + 'static,
{
    /// Builds a lifecycle control plane from a scenario catalog and loop factory.
    #[must_use]
    pub fn new<F>(
        server_name: impl Into<String>,
        scenarios: Vec<ScenarioCatalogEntry>,
        loop_factory: F,
    ) -> Self
    where
        F: Fn(&ScenarioDef, Seed) -> L + Send + Sync + 'static,
    {
        Self::new_with_source_factory(server_name, scenarios, move |scenario, _source, seed| {
            loop_factory(scenario, seed)
        })
    }

    /// Builds a lifecycle control plane from a source-aware loop factory.
    #[must_use]
    pub fn new_with_source_factory<F>(
        server_name: impl Into<String>,
        scenarios: Vec<ScenarioCatalogEntry>,
        loop_factory: F,
    ) -> Self
    where
        F: Fn(&ScenarioDef, Option<&ScenarioDefForm>, Seed) -> L + Send + Sync + 'static,
    {
        Self::new_with_fallible_source_factory(
            server_name,
            scenarios,
            move |scenario, source, seed| Ok(loop_factory(scenario, source, seed)),
        )
    }

    /// Builds a lifecycle control plane from a fallible source-aware loop factory.
    ///
    /// This is the production backend seam: process launch, artifact
    /// realization, or backend admission failures are returned through
    /// [`LifecycleApiError::LoopFactory`] instead of being replaced by a test
    /// double or converted into a panic.
    #[must_use]
    pub fn new_with_fallible_source_factory<F>(
        server_name: impl Into<String>,
        scenarios: Vec<ScenarioCatalogEntry>,
        loop_factory: F,
    ) -> Self
    where
        F: Fn(&ScenarioDef, Option<&ScenarioDefForm>, Seed) -> Result<L, LifecycleApiError>
            + Send
            + Sync
            + 'static,
    {
        let scenarios = scenarios
            .into_iter()
            .map(|entry| (entry.name.clone(), entry))
            .collect();
        Self {
            server_name: server_name.into(),
            scenarios,
            sessions: BTreeMap::new(),
            next_session_id: 1,
            next_epoch: 1,
            loop_factory: Box::new(loop_factory),
            white_box_policy_provider: Box::new(|_| BTreeMap::new()),
            mailbox_capacity: LIFECYCLE_SESSION_MAILBOX_CAPACITY,
            startup_max_actor_yields: LIFECYCLE_SESSION_STARTUP_MAX_ACTOR_YIELDS,
            max_sessions: None,
            resume_via_thin_replay: false,
            _loop: PhantomData,
        }
    }
}
