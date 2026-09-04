// crucible-lint: allow panic-shortcut -- fixtures use panic shortcuts for precise failures.
#![allow(clippy::expect_used)]

use crucible_campaign::ExactCheckpointId;
use crucible_cas::content_store::{ContentId, ObjectKind};
use crucible_qemu::QemuQmpVmStateControlChannel;

use super::*;
use crate::{
    AttemptExecutionDisposition, AttemptExecutionReconciliationStep, HotCheckpointFallback,
    HotCheckpointFallbackRetentionAdmin, HotCheckpointHotnessSignals, HotCheckpointResourceProfile,
    QemuAttemptOperationalBoundary, QemuHotForkAttemptLifecycle, QemuHotForkChildExitPolicy,
    QemuHotForkLiveExecution, QemuHotForkTemplateKey,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[error("scripted durable managed-pool failure")]
struct ScriptedError;

struct NeverLive;

impl QemuAttemptOperationalBoundary for NeverLive {
    fn resource_limits(&self) -> crucible_campaign::AttemptResourceLimits {
        panic!("scripted lifecycle never becomes live")
    }

    fn cancellation(&self) -> &crate::ExecutionCancellation {
        panic!("scripted lifecycle never becomes live")
    }

    fn check_operational_boundary(&mut self) -> Result<(), crucible_qemu::QemuVmRealizationError> {
        panic!("scripted lifecycle never becomes live")
    }

    fn charge_execution_quantum(&mut self) -> Result<(), crucible_qemu::QemuVmRealizationError> {
        panic!("scripted lifecycle never becomes live")
    }
}

impl QemuHotForkLiveExecution for NeverLive {
    fn child_qmp_mut(
        &mut self,
    ) -> &mut QemuQmpVmStateControlChannel<std::os::unix::net::UnixStream> {
        panic!("scripted lifecycle never becomes live")
    }

    fn host_continuation_mut(&mut self) -> &mut crucible_qemu::QemuHotForkHostContinuation {
        panic!("scripted lifecycle never becomes live")
    }

    fn event_log_mut(&mut self) -> &mut crucible::EventLog {
        panic!("scripted lifecycle never becomes live")
    }

    fn drain_diagnostics(
        &mut self,
    ) -> Result<crucible_qemu::QemuHotForkChildDiagnosticDrain, crucible_qemu::QemuVmRealizationError>
    {
        panic!("scripted lifecycle never becomes live")
    }
}

struct ScriptedLifecycle;

impl QemuHotForkAttemptLifecycle for ScriptedLifecycle {
    type Live<'a> = NeverLive;
    type Error = ScriptedError;

    fn runtime_basis(&self) -> AttemptExecutionRuntimeBasis {
        panic!("scripted lifecycle is not started")
    }

    fn admit_child(&mut self) -> Result<(), Self::Error> {
        panic!("scripted lifecycle is not started")
    }

    fn live_child(&mut self) -> Result<Self::Live<'_>, Self::Error> {
        panic!("scripted lifecycle is not started")
    }

    fn stop_before_publication(
        &mut self,
        _exit_policy: QemuHotForkChildExitPolicy,
    ) -> Result<(), Self::Error> {
        panic!("scripted lifecycle is not started")
    }

    fn reconcile_execution_disposition(
        &mut self,
        _disposition: AttemptExecutionDisposition,
    ) -> Result<AttemptExecutionReconciliationStep, AttemptWorkerFailure<Self::Error>> {
        panic!("scripted lifecycle is not started")
    }

    fn quarantine(&mut self) {}
}

struct ScriptedFactory {
    key: QemuHotForkTemplateKey,
}

impl QemuHotForkAttemptLifecycleFactory for ScriptedFactory {
    type Lifecycle = ScriptedLifecycle;
    type Error = ScriptedError;

    fn start(
        &mut self,
        _input: &CrucibleAttemptExecution,
        _context: &AttemptExecutionContext,
        _runtime_basis: AttemptExecutionRuntimeBasis,
    ) -> Result<Self::Lifecycle, AttemptWorkerFailure<Self::Error>> {
        Err(AttemptWorkerFailure::Retryable(ScriptedError))
    }

    fn recover(
        &mut self,
        lifecycle: Self::Lifecycle,
    ) -> Result<(), QemuHotForkAttemptLifecycleRecoveryError<Self::Lifecycle, Self::Error>> {
        Err(QemuHotForkAttemptLifecycleRecoveryError::new(
            lifecycle,
            AttemptWorkerFailure::Terminal(ScriptedError),
        ))
    }

    fn quarantine(&mut self, _lifecycle: Self::Lifecycle) {}
}

impl crate::qemu_hot_fork_pool::sealed::QemuHotForkKeyedLifecycleFactory for ScriptedFactory {}

impl QemuHotForkKeyedLifecycleFactory for ScriptedFactory {
    fn template_key(&self) -> QemuHotForkTemplateKey {
        self.key
    }

    fn template_available(&self) -> bool {
        true
    }
}

#[derive(Default)]
struct ScriptedQuarantine;

impl QemuHotForkLifecycleQuarantine<QemuHotForkTemplatePoolLifecycle<ScriptedLifecycle>>
    for ScriptedQuarantine
{
    fn retain_lifecycle(
        &mut self,
        _lifecycle: QemuHotForkTemplatePoolLifecycle<ScriptedLifecycle>,
    ) {
    }
}

#[derive(Default)]
struct ScriptedDemotions;

impl HotCheckpointTemplateDemotionSink<ScriptedFactory> for ScriptedDemotions {
    type Error = ScriptedError;

    fn validate_fallback(
        &mut self,
        _key: QemuHotForkTemplateKey,
        _fallback: HotCheckpointFallback,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn demote(
        &mut self,
        _factory: ScriptedFactory,
        _plan: crate::HotCheckpointPlannedDemotion,
    ) -> Result<(), crate::HotCheckpointTemplateDemotionFailure<ScriptedFactory, Self::Error>> {
        Ok(())
    }
}

#[derive(Clone)]
struct FailRemovalStore {
    inner: crate::MemoryHotCheckpointFallbackRetentionStore,
}

impl HotCheckpointFallbackRetentionAdmin for FailRemovalStore {
    fn acquire_hot_checkpoint_retention_fence(
        &self,
    ) -> Result<
        Box<dyn crate::HotCheckpointFallbackRetentionFence + '_>,
        HotCheckpointFallbackRetentionError,
    > {
        self.inner.acquire_hot_checkpoint_retention_fence()
    }
}

impl HotCheckpointFallbackRetentionStore for FailRemovalStore {
    fn load_fallback(
        &self,
        slot: HotCheckpointFallbackSlot,
    ) -> Result<Option<HotCheckpointFallbackRecord>, HotCheckpointFallbackRetentionError> {
        self.inner.load_fallback(slot)
    }

    fn compare_exchange_fallback(
        &self,
        slot: HotCheckpointFallbackSlot,
        expected: Option<HotCheckpointFallbackRecord>,
        next: Option<HotCheckpointFallbackRecord>,
    ) -> Result<HotCheckpointFallbackRetentionCas, HotCheckpointFallbackRetentionError> {
        if next.is_none() {
            return Err(HotCheckpointFallbackRetentionError::Poisoned);
        }
        self.inner.compare_exchange_fallback(slot, expected, next)
    }
}

#[test]
fn admission_roots_before_install_and_demotion_preserves_cold_fallbacks() {
    let retention = crate::MemoryHotCheckpointFallbackRetentionStore::new();
    let mut owner = owner(1, unit_resources(), retention.clone());

    let first = owner
        .admit_template(factory(1), candidate(1, 1, unit_resources()))
        .expect("first durable admission");
    let first_source = first.retained().slot();
    let first_catalog = owner
        .active_fallback_slot(first_source)
        .expect("first catalog binding");
    assert_eq!(
        retention
            .load_fallback(first_catalog)
            .expect("durable first"),
        owner.fallback_record(first_catalog)
    );

    let second = owner
        .admit_template(factory(2), candidate(2, 2, unit_resources()))
        .expect("hotter replacement");
    assert_eq!(second.demoted().len(), 1);
    assert_eq!(second.demoted()[0].status().slot(), first_source);
    assert_eq!(owner.active_fallback_slot(first_source), None);
    assert!(owner.fallback_record(first_catalog).is_some());

    let second_source = second.retained().slot();
    let second_catalog = owner
        .active_fallback_slot(second_source)
        .expect("second catalog binding");
    owner
        .demote_template(second_source, HotCheckpointDemotionReason::OperatorRequest)
        .expect("explicit demotion");
    assert_eq!(owner.active_fallback_slot(second_source), None);
    assert_eq!(owner.cold_fallbacks().count(), 2);

    owner
        .release_cold_fallback(first_catalog)
        .expect("release first");
    owner
        .release_cold_fallback(second_catalog)
        .expect("release second");
    assert_eq!(owner.cold_fallbacks().count(), 0);
}

#[test]
fn restart_reconstructs_all_records_as_cold_without_claiming_live_sources() {
    let retention = crate::MemoryHotCheckpointFallbackRetentionStore::new();
    let catalog_slot;
    {
        let mut owner = owner(1, unit_resources(), retention.clone());
        let commit = owner
            .admit_template(factory(3), candidate(3, 3, unit_resources()))
            .expect("admission");
        catalog_slot = owner
            .active_fallback_slot(commit.retained().slot())
            .expect("active catalog slot");
    }

    let mut restarted = owner(1, unit_resources(), retention);
    assert_eq!(restarted.manager().usage().templates(), 0);
    assert_eq!(restarted.pool().first_slot(), None);
    assert_eq!(restarted.cold_fallbacks().count(), 1);
    assert!(restarted.fallback_record(catalog_slot).is_some());
    restarted
        .release_cold_fallback(catalog_slot)
        .expect("restart release");
}

#[test]
fn directory_restart_preserves_the_fallback_but_not_live_process_state() {
    let directory = tempfile::tempdir().expect("catalog directory");
    let catalog_slot;
    {
        let retention = crate::DirectoryHotCheckpointFallbackRetentionStore::open(directory.path())
            .expect("open catalog");
        let mut owner = owner(1, unit_resources(), retention);
        let commit = owner
            .admit_template(factory(7), candidate(7, 7, unit_resources()))
            .expect("admission");
        catalog_slot = owner
            .active_fallback_slot(commit.retained().slot())
            .expect("active catalog slot");
    }

    let retention = crate::DirectoryHotCheckpointFallbackRetentionStore::open(directory.path())
        .expect("reopen catalog");
    let mut restarted = owner(1, unit_resources(), retention);
    assert_eq!(restarted.manager().usage().templates(), 0);
    assert_eq!(restarted.cold_fallbacks().count(), 1);
    restarted
        .release_cold_fallback(catalog_slot)
        .expect("release restarted fallback");
    drop(restarted);

    let empty = crate::DirectoryHotCheckpointFallbackRetentionStore::open(directory.path())
        .expect("reopen empty catalog");
    assert_eq!(inventory_records(&empty).expect("empty inventory").len(), 0);
}

#[test]
fn rejected_admission_removes_its_provisional_catalog_record() {
    let retention = crate::MemoryHotCheckpointFallbackRetentionStore::new();
    let mut owner = owner(1, unit_resources(), retention.clone());
    let oversized = resources(11, 10, 1, 1, 10, 1);

    let failure = owner
        .admit_template(factory(4), candidate(4, 4, oversized))
        .expect_err("oversized admission");
    let (candidate, stranded, cleanup_slot, error) = failure.into_parts();
    assert!(candidate.is_some());
    assert!(stranded.is_none());
    assert_eq!(cleanup_slot, None);
    assert!(matches!(
        error,
        DurableManagedHotCheckpointAdmissionError::Managed(
            ManagedHotCheckpointAdmissionError::Rejected(_)
        )
    ));
    assert_eq!(inventory_records(&retention).expect("inventory").len(), 0);
}

#[test]
fn cleanup_failure_returns_the_exact_still_rooted_catalog_slot() {
    let inner = crate::MemoryHotCheckpointFallbackRetentionStore::new();
    let retention = FailRemovalStore {
        inner: inner.clone(),
    };
    let mut owner = owner(1, unit_resources(), retention);
    let oversized = resources(11, 10, 1, 1, 10, 1);

    let failure = owner
        .admit_template(factory(5), candidate(5, 5, oversized))
        .expect_err("oversized admission with failed cleanup");
    let (candidate, stranded, cleanup_slot, error) = failure.into_parts();
    assert!(candidate.is_some());
    assert!(stranded.is_none());
    let cleanup_slot = cleanup_slot.expect("retained cleanup slot");
    assert!(matches!(
        error,
        DurableManagedHotCheckpointAdmissionError::Cleanup { .. }
    ));
    assert!(
        inner
            .load_fallback(cleanup_slot)
            .expect("retained record")
            .is_some()
    );
}

#[test]
fn active_fallback_cannot_be_released() {
    let retention = crate::MemoryHotCheckpointFallbackRetentionStore::new();
    let mut owner = owner(1, unit_resources(), retention);
    let commit = owner
        .admit_template(factory(6), candidate(6, 6, unit_resources()))
        .expect("admission");
    let catalog_slot = owner
        .active_fallback_slot(commit.retained().slot())
        .expect("catalog slot");

    assert!(matches!(
        owner.release_cold_fallback(catalog_slot),
        Err(DurableManagedHotCheckpointReleaseError::Active)
    ));
    assert!(owner.fallback_record(catalog_slot).is_some());
}

#[test]
fn unresolved_installed_source_keeps_its_fallback_nonreleasable() {
    let retention = crate::MemoryHotCheckpointFallbackRetentionStore::new();
    let mut owner = owner(1, unit_resources(), retention);
    let commit = owner
        .admit_template(factory(7), candidate(7, 7, unit_resources()))
        .expect("durable admission");
    let source_slot = commit.retained().slot();
    let catalog_slot = owner
        .active
        .remove(&source_slot)
        .expect("active catalog binding");
    owner.unresolved.insert(catalog_slot, source_slot);

    assert_eq!(
        owner.unresolved_source_slot(catalog_slot),
        Some(source_slot)
    );
    assert_eq!(owner.cold_fallbacks().count(), 0);
    assert!(matches!(
        owner.release_cold_fallback(catalog_slot),
        Err(DurableManagedHotCheckpointReleaseError::Unresolved)
    ));
    assert!(owner.fallback_record(catalog_slot).is_some());
}

#[test]
fn full_catalog_rejects_before_live_source_ownership_changes() {
    let retention = crate::MemoryHotCheckpointFallbackRetentionStore::new();
    let occupied = HotCheckpointFallbackRecord::new(key(8), exact_fallback(8));
    for index in 0..MAX_HOT_CHECKPOINT_FALLBACK_ROOTS {
        let slot = HotCheckpointFallbackSlot::new(index).expect("bounded slot");
        assert_eq!(
            retention
                .compare_exchange_fallback(slot, None, Some(occupied))
                .expect("fill catalog"),
            HotCheckpointFallbackRetentionCas::Advanced
        );
    }
    let mut owner = owner(1, unit_resources(), retention);

    let failure = owner
        .admit_template(factory(9), candidate(9, 9, unit_resources()))
        .expect_err("full catalog");
    let (candidate, stranded, cleanup_slot, error) = failure.into_parts();
    assert!(candidate.is_some());
    assert!(stranded.is_none());
    assert_eq!(cleanup_slot, None);
    assert!(matches!(
        error,
        DurableManagedHotCheckpointAdmissionError::CatalogFull
    ));
    assert_eq!(owner.manager().usage().templates(), 0);
    assert_eq!(owner.pool().slot_count(), 0);
}

fn owner<R>(
    maximum_templates: usize,
    maximum_resources: HotCheckpointResourceProfile,
    retention: R,
) -> DurableManagedQemuHotForkTemplatePool<ScriptedFactory, ScriptedQuarantine, ScriptedDemotions, R>
where
    R: HotCheckpointFallbackRetentionStore,
{
    let limits = HotCheckpointLimits::new(maximum_templates, maximum_resources, 4, u64::MAX)
        .expect("limits");
    DurableManagedQemuHotForkTemplatePool::open(
        limits,
        ScriptedQuarantine,
        ScriptedDemotions,
        retention,
    )
    .expect("durable managed owner")
}

fn factory(byte: u8) -> ScriptedFactory {
    ScriptedFactory { key: key(byte) }
}

fn candidate(
    byte: u8,
    score: u64,
    resources: HotCheckpointResourceProfile,
) -> HotCheckpointCandidate {
    HotCheckpointCandidate::new(key(byte), resources, signals(score), exact_fallback(byte))
}

fn exact_fallback(byte: u8) -> HotCheckpointFallback {
    HotCheckpointFallback::Exact(
        ExactCheckpointId::try_from(ContentId::for_bytes(ObjectKind::ExactManifest, 4, &[byte]))
            .expect("exact fallback"),
    )
}

fn signals(score: u64) -> HotCheckpointHotnessSignals {
    HotCheckpointHotnessSignals::new()
        .with_pending_attempts(score)
        .expect("signals")
}

fn resources(
    template_bytes: u64,
    expected_private_dirty_bytes: u64,
    process_count: u32,
    virtual_cpu_count: u32,
    descriptor_count: u32,
    overlay_count: u32,
) -> HotCheckpointResourceProfile {
    HotCheckpointResourceProfile::new(
        template_bytes,
        expected_private_dirty_bytes,
        process_count,
        virtual_cpu_count,
        descriptor_count,
        overlay_count,
    )
    .expect("resources")
}

fn unit_resources() -> HotCheckpointResourceProfile {
    resources(10, 10, 1, 1, 10, 1)
}

fn key(byte: u8) -> QemuHotForkTemplateKey {
    QemuHotForkTemplateKey::new(
        crucible_campaign::CampaignLineageId::parse(&typed_id(
            "crucible.campaign.lineage",
            "campaign-fact",
            byte,
        ))
        .expect("lineage"),
        crucible::ContentHash::from_bytes(&[byte]),
    )
}

fn typed_id(tag: &str, kind: &str, byte: u8) -> String {
    format!("{tag}@{kind}.1.{}", encode_hex(&[byte; 32]))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}
