//! Aggregate chronological lifetime-cohort falsifier.
//!
//! This compile-time-only probe samples complete evaluator roots after selected
//! exact final-config executions and once at terminal demand quiescence. It
//! intentionally records no per-allocation or per-edge events. Consecutive
//! population deltas therefore give exact allocation-volume intervals and
//! conservative survivor bounds. The residual-retirement shadow window also
//! retains unreachable stable addresses and uses existing object touch epochs
//! plus later complete-root scans to falsify early retirement without reclaiming
//! memory. It does not prove that raw value words had no between-checkpoint
//! semantic observation.

use super::*;
use crate::eval::heap::LifetimeQuarantineInstallReport;
use std::collections::HashSet;

const DEFAULT_CHECKPOINTS: &[usize] = &[160, 176, 192, 224, 256, 288, 320, 352, 357];

/// Default-off state retained by one admitted serial evaluator.
#[derive(Debug)]
pub(super) struct LifetimeCohortProbe {
    checkpoints: Vec<usize>,
    successful_final_config_executions: usize,
    previous: Option<LifetimeCohortCensus>,
    candidates: Vec<LifetimeCohortCandidate>,
    candidate_addresses: HashSet<usize>,
    classifications: Vec<LifetimeCohortCandidateObservation>,
    terminal_emitted: bool,
}

impl LifetimeCohortProbe {
    /// Constructs the probe only for its strict, nonmoving serial experiment.
    pub(super) fn from_env(options: &TreeWalkOptions, force_cache_active: bool) -> Option<Self> {
        if !std::env::var("AOS_NIX_LIFETIME_COHORT_PROBE").is_ok_and(|value| value == "1") {
            return None;
        }
        let admitted = options.parallel_workers().is_none()
            && !options.parallel_thunk_payloads_enabled()
            && options.gc_mode() == EvalGcMode::Off
            && options.gc_stress_policy() == GcStressPolicy::disabled()
            && options.thunk_resolve_barrier_tier() == GenerationalGcTier::OneShotArena
            && !options.record_worker_closures_for_gc_scaffolding()
            && !options.eval_cache_enabled()
            && options.persist_cache_root().is_none()
            && !force_cache_active
            && !options.jit_tier1_publish_enabled()
            && !options.memo_active()
            && !options.boundary_memo_active();
        if !admitted {
            eprintln!(
                "aos_nix_lifetime_cohort_refused \
                 {{\"reason\":\"requires serial nonmoving cache/JIT/memo-off mode\"}}"
            );
            return None;
        }
        let checkpoints = std::env::var("AOS_NIX_LIFETIME_COHORT_CHECKPOINTS")
            .ok()
            .and_then(|value| parse_checkpoint_schedule(&value))
            .unwrap_or_else(|| DEFAULT_CHECKPOINTS.to_vec());
        Some(Self {
            checkpoints,
            successful_final_config_executions: 0,
            previous: None,
            candidates: Vec::new(),
            candidate_addresses: HashSet::new(),
            classifications: Vec::new(),
            terminal_emitted: false,
        })
    }

    /// Advances the local execution ordinal and returns a selected checkpoint.
    fn next_final_config_checkpoint(&mut self) -> Option<usize> {
        self.successful_final_config_executions =
            self.successful_final_config_executions.saturating_add(1);
        self.checkpoints
            .binary_search(&self.successful_final_config_executions)
            .is_ok()
            .then_some(self.successful_final_config_executions)
    }
}

impl TreeWalk {
    /// Samples one selected successful final-config execution.
    pub(super) fn note_lifetime_cohort_final_config(&mut self, value: Value) {
        let checkpoint = self
            .lifetime_cohort_probe
            .as_mut()
            .and_then(LifetimeCohortProbe::next_final_config_checkpoint);
        let Some(execution) = checkpoint else {
            return;
        };
        self.emit_lifetime_cohort_snapshot("final-config", execution, value);
    }

    /// Samples terminal demand quiescence at most once.
    pub(super) fn emit_lifetime_cohort_terminal(&mut self, value: Value) {
        let Some(probe) = self.lifetime_cohort_probe.as_mut() else {
            return;
        };
        if probe.terminal_emitted {
            return;
        }
        probe.terminal_emitted = true;
        let execution = probe.successful_final_config_executions;
        if self.heap.lifetime_quarantine_is_installed() {
            let roots = self.mutator_root_set().and_then(|mut roots| {
                roots
                    .try_push_value_stack(0, value)
                    .map_err(TreeWalkSafepointRootError::RootSet)?;
                Ok(roots)
            });
            match roots.and_then(|roots| {
                self.heap
                    .emit_lifetime_quarantine_terminal_reachability(&roots)
                    .map_err(TreeWalkSafepointRootError::Heap)
            }) {
                Ok(()) => {}
                Err(error) => eprintln!(
                    "aos_nix_lifetime_cohort_error \
                     {{\"kind\":\"terminal-quarantine\",\"execution\":{execution},\
                     \"error\":{error:?}}}"
                ),
            }
            self.heap.emit_lifetime_quarantine_report();
            return;
        }
        self.emit_lifetime_cohort_snapshot("terminal", execution, value);
        self.heap.emit_lifetime_quarantine_report();
    }

    fn emit_lifetime_cohort_snapshot(
        &mut self,
        kind: &'static str,
        execution: usize,
        value: Value,
    ) {
        let roots = self.mutator_root_set().and_then(|mut roots| {
            roots
                .try_push_value_stack(0, value)
                .map_err(TreeWalkSafepointRootError::RootSet)?;
            Ok(roots)
        });
        let roots = match roots {
            Ok(roots) => roots,
            Err(error) => {
                eprintln!(
                    "aos_nix_lifetime_cohort_error \
                     {{\"kind\":\"{kind}\",\"execution\":{execution},\
                     \"error\":{error:?}}}"
                );
                return;
            }
        };
        let snapshot = {
            let Some(probe) = self.lifetime_cohort_probe.as_ref() else {
                return;
            };
            self.heap.lifetime_cohort_census(&roots, &probe.candidates)
        };
        let snapshot = match snapshot {
            Ok(snapshot) => snapshot,
            Err(error) => {
                eprintln!(
                    "aos_nix_lifetime_cohort_error \
                     {{\"kind\":\"{kind}\",\"execution\":{execution},\
                     \"error\":{error:?}}}"
                );
                return;
            }
        };
        let current_inventory_objects = snapshot.unreachable_candidates.len() as u64;
        let current_inventory_bytes = snapshot
            .unreachable_candidates
            .iter()
            .fold(0_u64, |total, candidate| {
                total.saturating_add(candidate.attributable_bytes())
            });
        if kind == "final-config" && execution == 176 {
            self.run_exec176_weak_purge(&snapshot.unreachable_candidates);
            match self
                .heap
                .install_lifetime_quarantine(&snapshot.unreachable_candidates)
            {
                LifetimeQuarantineInstallReport::Installed {
                    objects,
                    bytes,
                    typed_heads_excluded,
                } => eprintln!(
                    "aos_nix_lifetime_quarantine_installed \
                     {{\"version\":1,\"execution\":176,\"objects\":{objects},\
                     \"bytes\":{bytes},\"typed_heads_excluded\":{typed_heads_excluded}}}"
                ),
                LifetimeQuarantineInstallReport::Refused { reason } => eprintln!(
                    "aos_nix_lifetime_quarantine_refused \
                     {{\"version\":1,\"execution\":176,\"reason\":{reason:?}}}"
                ),
            }
        }
        let Some(probe) = self.lifetime_cohort_probe.as_mut() else {
            return;
        };
        for (classification, observation) in probe
            .classifications
            .iter_mut()
            .zip(snapshot.prior_observations.iter().copied())
        {
            *classification = stronger_observation(*classification, observation);
        }
        let additional_candidates = snapshot.unreachable_candidates.len();
        if probe.candidates.try_reserve(additional_candidates).is_err()
            || probe
                .classifications
                .try_reserve(additional_candidates)
                .is_err()
            || probe
                .candidate_addresses
                .try_reserve(additional_candidates)
                .is_err()
        {
            eprintln!(
                "aos_nix_lifetime_cohort_error \
                 {{\"kind\":\"{kind}\",\"execution\":{execution},\
                 \"error\":\"residual-retirement candidate storage allocation failed\"}}"
            );
            return;
        }
        for candidate in snapshot.unreachable_candidates.iter().copied() {
            if !probe.candidate_addresses.insert(candidate.address) {
                continue;
            }
            probe.candidates.push(candidate);
            probe
                .classifications
                .push(if candidate.initial_touch_epoch.is_some() {
                    LifetimeCohortCandidateObservation::Pending
                } else {
                    LifetimeCohortCandidateObservation::NoEpoch
                });
        }
        let census = snapshot.census;
        let previous = probe.previous;
        probe.previous = Some(census);
        emit_residual_retirement_report(
            kind,
            execution,
            census,
            &probe.candidates,
            &probe.classifications,
            current_inventory_objects,
            current_inventory_bytes,
        );
        emit_census_report(
            kind,
            execution,
            self.modules.len(),
            self.heap.allocation_counters().values_allocated(),
            previous,
            census,
        );
    }
}

fn stronger_observation(
    prior: LifetimeCohortCandidateObservation,
    current: LifetimeCohortCandidateObservation,
) -> LifetimeCohortCandidateObservation {
    use LifetimeCohortCandidateObservation::{
        Cold, NoEpoch, Pending, Resurrected, Touched, VanishedOrReused,
    };
    match (prior, current) {
        (VanishedOrReused, _) | (_, VanishedOrReused) => VanishedOrReused,
        (NoEpoch, _) | (_, NoEpoch) => NoEpoch,
        (Resurrected, _) | (_, Resurrected) => Resurrected,
        (Touched, _) | (_, Touched) => Touched,
        (Pending, observed) => observed,
        (observed, Pending) => observed,
        (Cold, Cold) => Cold,
    }
}

fn emit_residual_retirement_report(
    kind: &str,
    execution: usize,
    census: LifetimeCohortCensus,
    candidates: &[LifetimeCohortCandidate],
    classifications: &[LifetimeCohortCandidateObservation],
    current_inventory_objects: u64,
    current_inventory_bytes: u64,
) {
    let mut classes = [(0_u64, 0_u64); 6];
    for (candidate, classification) in candidates.iter().zip(classifications) {
        let index = match classification {
            LifetimeCohortCandidateObservation::Pending => 0,
            LifetimeCohortCandidateObservation::Cold => 1,
            LifetimeCohortCandidateObservation::Touched => 2,
            LifetimeCohortCandidateObservation::Resurrected => 3,
            LifetimeCohortCandidateObservation::VanishedOrReused => 4,
            LifetimeCohortCandidateObservation::NoEpoch => 5,
        };
        classes[index].0 = classes[index].0.saturating_add(1);
        classes[index].1 = classes[index]
            .1
            .saturating_add(candidate.attributable_bytes());
    }
    let inventory_objects = census.unreachable.objects;
    let inventory_bytes = census.unreachable.total_bytes();
    let tracked_bytes = candidates.iter().fold(0_u64, |total, candidate| {
        total.saturating_add(candidate.attributable_bytes())
    });
    eprintln!(
        "aos_nix_residual_retirement_shadow \
         {{\"version\":1,\"checkpoint\":{{\"kind\":\"{kind}\",\"execution\":{execution}}},\
         \"current_unreachable\":[{inventory_objects},{inventory_bytes}],\
         \"tracked\":[{},{}],\
         \"classes\":{{\"pending\":[{},{}],\"cold\":[{},{}],\"touched\":[{},{}],\
         \"resurrected\":[{},{}],\"vanished_or_reused\":[{},{}],\
         \"no_epoch_pinned\":[{},{}]}},\
         \"tracked_bytes_reconciled\":{},\
         \"current_inventory_bytes_reconciled\":{},\
         \"claims\":{{\"hash_indexes_are_roots\":false,\
         \"between_final_config_raw_word_observation\":\"unknown\",\
         \"retirement_performed\":false}}}}",
        candidates.len(),
        tracked_bytes,
        classes[0].0,
        classes[0].1,
        classes[1].0,
        classes[1].1,
        classes[2].0,
        classes[2].1,
        classes[3].0,
        classes[3].1,
        classes[4].0,
        classes[4].1,
        classes[5].0,
        classes[5].1,
        classes
            .iter()
            .fold(0_u64, |total, class| total.saturating_add(class.1))
            == tracked_bytes,
        current_inventory_objects == inventory_objects
            && current_inventory_bytes == inventory_bytes,
    );
}

fn emit_census_report(
    kind: &str,
    execution: usize,
    modules: usize,
    allocation_ordinal: u64,
    previous: Option<LifetimeCohortCensus>,
    census: LifetimeCohortCensus,
) {
    let previous_total = previous.map_or(0, |sample| sample.total.total_bytes());
    let previous_objects = previous.map_or(0, |sample| sample.total.objects);
    let interval_bytes = census.total.total_bytes().saturating_sub(previous_total);
    let interval_objects = census.total.objects.saturating_sub(previous_objects);
    let reachable = subtract_mass(census.total, census.unreachable);
    let all_bounds = survivor_bounds(previous_total, interval_bytes, reachable.total_bytes());
    let ready_bounds = survivor_bounds(
        previous_total,
        interval_bytes,
        census.ready_only.total_bytes(),
    );
    let other_bounds = survivor_bounds(
        previous_total,
        interval_bytes,
        census
            .other_only
            .total_bytes()
            .saturating_add(census.shared.total_bytes()),
    );
    eprintln!(
        "aos_nix_lifetime_cohort \
         {{\"version\":1,\"checkpoint\":{{\"kind\":\"{kind}\",\
         \"execution\":{execution},\"modules\":{modules},\
         \"allocation_ordinal\":{allocation_ordinal}}},\
         \"interval\":{{\"objects\":{interval_objects},\"bytes\":{interval_bytes},\
         \"survivor_bounds\":{{\"all\":[{},{}],\"ready_only\":[{},{}],\
         \"other_or_shared\":[{},{}]}}}},\
         \"roots\":{{\"ready\":{},\"other\":{},\"union_reconciled\":{}}},\
         \"mass\":{{\"total\":[{},{},{}],\"reachable\":[{},{},{}],\
         \"ready_only\":[{},{},{}],\"other_only\":[{},{},{}],\
         \"shared\":[{},{},{}],\"unreachable\":[{},{},{}]}},\
         \"stores\":{{\"records\":{},\"strings_paths\":[{},{}],\
         \"lists\":[{},{}],\"attrs\":[{},{}],\"closures\":[{},{}],\
         \"typed_heads\":[{},{}],\"typed_work\":[{},{},{},{}],\
         \"boxed_scalars_pinned\":[{},{}],\"hash_cons\":[{},{},{},{}]}},\
         \"claims\":{{\"later_read_of_residual_dead_edge\":\"unknown\",\
         \"exact_escape_edge_attribution\":\"unknown\",\
         \"cross_kind_order_within_interval\":\"unknown\",\
         \"probe_rss_is_acceptance_rss\":false}}}}",
        all_bounds.0,
        all_bounds.1,
        ready_bounds.0,
        ready_bounds.1,
        other_bounds.0,
        other_bounds.1,
        census.ready_roots,
        census.other_roots,
        census.union_reconciled,
        census.total.objects,
        census.total.inline_bytes,
        census.total.external_bytes,
        reachable.objects,
        reachable.inline_bytes,
        reachable.external_bytes,
        census.ready_only.objects,
        census.ready_only.inline_bytes,
        census.ready_only.external_bytes,
        census.other_only.objects,
        census.other_only.inline_bytes,
        census.other_only.external_bytes,
        census.shared.objects,
        census.shared.inline_bytes,
        census.shared.external_bytes,
        census.unreachable.objects,
        census.unreachable.inline_bytes,
        census.unreachable.external_bytes,
        census.records,
        census.strings_paths[0],
        census.strings_paths[1],
        census.lists[0],
        census.lists[1],
        census.attrs[0],
        census.attrs[1],
        census.closures[0],
        census.closures[1],
        census.typed_heads[0],
        census.typed_heads[1],
        census.typed_work[0],
        census.typed_work[1],
        census.typed_work[2],
        census.typed_work[3],
        census.boxed_scalars[0],
        census.boxed_scalars[1],
        census.hash_cons[0],
        census.hash_cons[1],
        census.hash_cons[2],
        census.hash_cons[3],
    );
}

fn parse_checkpoint_schedule(value: &str) -> Option<Vec<usize>> {
    let mut checkpoints = value
        .split(',')
        .map(str::trim)
        .map(str::parse::<usize>)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    if checkpoints.is_empty() || checkpoints.contains(&0) {
        return None;
    }
    checkpoints.sort_unstable();
    checkpoints.dedup();
    Some(checkpoints)
}

fn survivor_bounds(previous_total: u64, interval: u64, current_class: u64) -> (u64, u64) {
    (
        current_class.saturating_sub(previous_total).min(interval),
        current_class.min(interval),
    )
}

fn subtract_mass(total: LifetimeCohortMass, part: LifetimeCohortMass) -> LifetimeCohortMass {
    LifetimeCohortMass {
        objects: total.objects.saturating_sub(part.objects),
        inline_bytes: total.inline_bytes.saturating_sub(part.inline_bytes),
        external_bytes: total.external_bytes.saturating_sub(part.external_bytes),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compile::resolve as resolve_ast;
    use crate::eval::heap::LifetimeCohortCandidateKind;
    use crate::syntax::parse_str;

    fn lower(source: &str) -> Ir {
        nix_lower(resolve_ast(parse_str(source).expect("source parses")).expect("source resolves"))
            .expect("source lowers")
    }

    #[test]
    fn checkpoint_schedule_sorts_and_deduplicates() {
        assert_eq!(
            parse_checkpoint_schedule("224, 160,224,192"),
            Some(vec![160, 192, 224])
        );
        assert_eq!(parse_checkpoint_schedule("0,160"), None);
        assert_eq!(parse_checkpoint_schedule("not-a-number"), None);
    }

    #[test]
    fn interval_survivor_bounds_are_conservative() {
        assert_eq!(survivor_bounds(100, 40, 25), (0, 25));
        assert_eq!(survivor_bounds(100, 40, 115), (15, 40));
        assert_eq!(survivor_bounds(100, 40, 200), (40, 40));
    }

    #[test]
    fn new_shadow_candidate_stays_pending_until_a_later_observation() {
        assert_eq!(
            stronger_observation(
                LifetimeCohortCandidateObservation::Pending,
                LifetimeCohortCandidateObservation::Cold,
            ),
            LifetimeCohortCandidateObservation::Cold
        );
        assert_eq!(
            stronger_observation(
                LifetimeCohortCandidateObservation::Pending,
                LifetimeCohortCandidateObservation::Touched,
            ),
            LifetimeCohortCandidateObservation::Touched
        );
    }

    #[test]
    fn installed_quarantine_terminal_skips_cumulative_cohort_inventory() {
        let ir = lower("null");
        let mut evaluator = TreeWalk::new(&ir);
        evaluator.lifetime_cohort_probe = Some(LifetimeCohortProbe {
            checkpoints: vec![176],
            successful_final_config_executions: 176,
            previous: None,
            candidates: Vec::new(),
            candidate_addresses: HashSet::new(),
            classifications: Vec::new(),
            terminal_emitted: false,
        });
        let value = evaluator
            .heap
            .alloc_string(NixString::from_bytes(b"terminal".to_vec()))
            .expect("terminal string allocates");
        let address = value
            .as_string_ptr()
            .expect("terminal string has a pointer")
            .as_ptr() as usize;
        let candidate = LifetimeCohortCandidate {
            address,
            kind: LifetimeCohortCandidateKind::String,
            inline_bytes: 32,
            external_bytes: 8,
            initial_touch_epoch: Some(1),
        };
        assert!(matches!(
            evaluator.heap.install_lifetime_quarantine(&[candidate]),
            LifetimeQuarantineInstallReport::Installed { objects: 1, .. }
        ));

        evaluator.emit_lifetime_cohort_terminal(value);

        let probe = evaluator
            .lifetime_cohort_probe
            .as_ref()
            .expect("probe remains installed");
        assert!(probe.terminal_emitted);
        assert!(probe.previous.is_none());
        assert!(probe.candidates.is_empty());
        assert!(probe.candidate_addresses.is_empty());
        assert!(probe.classifications.is_empty());
    }
}
