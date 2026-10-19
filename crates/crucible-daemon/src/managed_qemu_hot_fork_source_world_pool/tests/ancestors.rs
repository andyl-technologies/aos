//! Ancestor checkout: the deepest eligible published root below a parent.

use crucible::{Configuration, Decision};
use crucible_campaign::ConfigurationArtifactId;
use crucible_cas::content_store::{ContentId, ObjectKind};

use super::super::test_support::{
    published_root_source_after_selections_for_test, scheduler_selection_for_test,
};
use super::*;
use crate::qemu_hot_fork_source_capture::{
    AuthenticatedPublishedRootQemuHotForkSource, QemuPublishedRootOrigin,
    QemuPublishedRootProvenance,
};

const LINEAGE: u8 = 0x61;

fn artifact(name: &str) -> ConfigurationArtifactId {
    ConfigurationArtifactId::parse(&format!(
        "crucible.campaign.configuration-artifact@{}",
        ContentId::for_bytes(ObjectKind::Configuration, 1, name.as_bytes()).encode()
    ))
    .expect("published artifact id")
}

fn published_key_at(configuration: &Configuration, lineage: u8) -> QemuHotForkSourceWorldKey {
    QemuHotForkSourceWorldKey::new_published(
        lineage_id(lineage),
        configuration.def.id(),
        configuration.id(),
        compatibility_profile(),
    )
}

/// Appends one more recorded scheduler selection to `configuration`.
fn descendant(configuration: &Configuration, name: &str) -> Configuration {
    let scenario = crucible::crash_restart_scenario()
        .expect("built-in scenario")
        .scenario;
    crucible::try_step(
        configuration,
        Decision::Selection(scheduler_selection_for_test(&scenario, name)),
    )
    .expect("descendant configuration")
}

/// Resources for `templates` measured roots plus `children` child leases.
fn limits_for(
    source: &mut ProductionVmHotForkSourceWorld,
    templates: usize,
    children: u64,
    forks: u32,
) -> HotCheckpointLimits {
    let usage = source
        .measure_retained_resources()
        .expect("measure source resources");
    // Worlds measure slightly differently; double every share for variance.
    let shares = (u64::try_from(templates).expect("template count") + children) * 2;
    let scale = |value: u64| value.saturating_mul(shares);
    let scale_count =
        |value: u32| u32::try_from(scale(u64::from(value))).expect("scaled count fits");
    let resources = HotCheckpointResourceProfile::new(
        scale(usage.template_bytes()),
        scale(usage.expected_private_dirty_bytes()),
        scale_count(usage.process_count()),
        scale_count(usage.virtual_cpu_count()),
        scale_count(usage.descriptor_count()),
        scale_count(usage.overlay_count()).max(1),
    )
    .expect("pool resource ceiling");
    HotCheckpointLimits::new(templates, resources, forks, u64::MAX).expect("managed limits")
}

/// A pool holding stop roots after `[a]` and `[a, b]`, and an unrelated `[z]`.
struct AncestorPool {
    pool: ManagedQemuHotForkSourceWorldPool<
        ReapingDemotionSink,
        MemoryHotCheckpointFallbackRetentionStore,
    >,
    shallow: Configuration,
    deep: Configuration,
}

impl AncestorPool {
    fn new(forks: u32) -> Self {
        let mut shallow = published_root_source_after_selections_for_test(&["ancestor.a"]);
        let deep = published_root_source_after_selections_for_test(&["ancestor.a", "ancestor.b"]);
        let unrelated = published_root_source_after_selections_for_test(&["ancestor.z"]);
        let limits = limits_for(&mut shallow, 3, 1, forks);
        let mut pool = ManagedQemuHotForkSourceWorldPool::open(
            limits,
            ReapingDemotionSink,
            MemoryHotCheckpointFallbackRetentionStore::new(),
        )
        .expect("managed source-world pool");

        let shallow_configuration = shallow.continuation().configuration().clone();
        let deep_configuration = deep.continuation().configuration().clone();
        for (name, source) in [
            ("ancestor-a", shallow),
            ("ancestor-ab", deep),
            ("ancestor-z", unrelated),
        ] {
            let configuration = source.continuation().configuration().clone();
            let provenance = QemuPublishedRootProvenance::new(
                QemuPublishedRootOrigin::AttemptStop,
                configuration.clone(),
                Some(true),
            );
            pool.admit_authenticated_published_root(
                AuthenticatedPublishedRootQemuHotForkSource::new(
                    published_key_at(&configuration, LINEAGE),
                    artifact(name),
                    source,
                    provenance,
                ),
                HotCheckpointHotnessSignals::new(),
            )
            .expect("admit published root");
        }

        Self {
            pool,
            shallow: shallow_configuration,
            deep: deep_configuration,
        }
    }

    /// Checks out an ancestor for `parent` and returns the root's configuration.
    fn ancestor_for(
        &mut self,
        key: &QemuHotForkSourceWorldKey,
        parent: &Configuration,
        eligible: &dyn Fn(&QemuPublishedRootProvenance) -> bool,
    ) -> Option<Configuration> {
        let checkout = self
            .pool
            .checkout_ancestor_lease_for(1, key, parent, eligible)
            .expect("ancestor checkout")?;
        let (lease, ancestor, provenance) = checkout.into_parts();
        assert_eq!(ancestor.configuration(), provenance.configuration().id());
        self.pool.restore_lease_for(1, lease);
        Some(provenance.configuration().clone())
    }
}

#[test]
fn ancestor_checkout_leases_the_deepest_strict_prefix_root() {
    let mut fixture = AncestorPool::new(4);
    let parent = descendant(&fixture.deep, "ancestor.c");
    let key = published_key_at(&parent, LINEAGE);
    assert!(
        fixture
            .pool
            .checkout(&key)
            .expect("exact checkout")
            .is_none()
    );

    let checkout = fixture
        .pool
        .checkout_ancestor_lease_for(1, &key, &parent, &|_| true)
        .expect("ancestor checkout")
        .expect("an ancestor root");
    let (lease, ancestor, provenance) = checkout.into_parts();

    assert_eq!(ancestor, published_key_at(&fixture.deep, LINEAGE));
    assert_eq!(provenance.configuration(), &fixture.deep);
    // The ancestor lease reserves one child exactly like an exact lease.
    assert_ne!(
        fixture.pool.source_lease_usage(),
        HotCheckpointUsage::default()
    );
    fixture.pool.restore_lease_for(1, lease);
    assert_eq!(
        fixture.pool.source_lease_usage(),
        HotCheckpointUsage::default()
    );
    assert!(fixture.pool.source_available(&ancestor));
    fixture.pool.orderly_shutdown().expect("retire roots");
}

#[test]
fn ancestor_checkout_excludes_roots_that_cannot_serve_the_parent() {
    let mut fixture = AncestorPool::new(16);
    let parent = descendant(&fixture.deep, "ancestor.c");
    let key = published_key_at(&parent, LINEAGE);
    let deep = fixture.deep.clone();
    let shallow = fixture.shallow.clone();

    // A root at the parent itself is not a strict ancestor.
    let at_deep = published_key_at(&deep, LINEAGE);
    assert_eq!(
        fixture.ancestor_for(&at_deep, &deep, &|_| true),
        Some(shallow.clone())
    );
    // A parent that diverges after `[a]` is served only by `[a]`.
    let diverged = descendant(&shallow, "ancestor.x");
    let diverged_key = published_key_at(&diverged, LINEAGE);
    assert_eq!(
        fixture.ancestor_for(&diverged_key, &diverged, &|_| true),
        Some(shallow.clone())
    );
    // The caller's suffix policy can veto the deepest root.
    let skip_deep = |provenance: &QemuPublishedRootProvenance| provenance.configuration() != &deep;
    assert_eq!(
        fixture.ancestor_for(&key, &parent, &skip_deep),
        Some(shallow.clone())
    );
    assert_eq!(fixture.ancestor_for(&key, &parent, &|_| false), None);
    // Another lineage shares no roots.
    let foreign = published_key_at(&parent, LINEAGE + 1);
    assert_eq!(fixture.ancestor_for(&foreign, &parent, &|_| true), None);
    // Only a published-boundary attempt key asks for ancestors.
    let canonical = QemuHotForkSourceWorldKey::new(
        lineage_id(LINEAGE),
        parent.def.id(),
        parent.id(),
        compatibility_profile(),
    );
    assert_eq!(fixture.ancestor_for(&canonical, &parent, &|_| true), None);

    // An invalidated root is never offered again.
    let lease = fixture
        .pool
        .checkout_lease_for(2, &at_deep)
        .expect("deep root lease")
        .expect("deep root");
    fixture.pool.abandon_lease_for(2);
    drop(lease);
    assert_eq!(
        fixture.ancestor_for(&key, &parent, &|_| true),
        Some(shallow)
    );
    // The abandoned root's authority stays in quarantine, not in the pool.
    assert!(fixture.pool.orderly_shutdown().is_err());
}

#[test]
fn ancestor_checkout_spends_fork_rate_and_refuses_beyond_it() {
    let mut fixture = AncestorPool::new(1);
    let parent = descendant(&fixture.deep, "ancestor.c");
    let key = published_key_at(&parent, LINEAGE);
    let deep = fixture.deep.clone();

    assert_eq!(fixture.ancestor_for(&key, &parent, &|_| true), Some(deep));
    let refused = fixture
        .pool
        .checkout_ancestor_lease_for(1, &key, &parent, &|_| true);

    assert!(matches!(
        refused,
        Err(ManagedQemuHotForkSourceWorldCheckoutError::ForkRate(_))
    ));
    // A refused checkout leaves no reservation behind.
    assert_eq!(
        fixture.pool.source_lease_usage(),
        HotCheckpointUsage::default()
    );
    fixture.pool.orderly_shutdown().expect("retire roots");
}

#[test]
fn shared_provider_forwards_ancestor_checkout_to_the_pool() {
    let fixture = AncestorPool::new(4);
    let parent = descendant(&fixture.deep, "ancestor.c");
    let key = published_key_at(&parent, LINEAGE);
    let shared = SharedManagedQemuHotForkSourceWorldPool::new(fixture.pool);
    let mut provider = shared.provider().expect("worker provider");

    let checkout = provider
        .checkout_ancestor(&key, &parent, &|_| true)
        .expect("forwarded ancestor checkout")
        .expect("an ancestor root");
    let (lease, ancestor, _provenance) = checkout.into_parts();

    assert_eq!(ancestor, published_key_at(&fixture.deep, LINEAGE));
    provider.restore(lease);
    drop(provider);
    shared.orderly_shutdown().expect("retire roots");
}
