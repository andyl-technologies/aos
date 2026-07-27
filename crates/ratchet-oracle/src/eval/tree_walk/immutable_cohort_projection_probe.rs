//! Report-only cadence for all-object immutable-cohort packing projections.
//!
//! The probe samples successful callback-free final-config completions. It
//! performs no collection, mutation, publication, or execution admission.

use std::collections::HashMap;

use crate::eval::heap::{ImmutableCohortFingerprint, ImmutableCohortProjection};
use crate::heap::ProcessResidentMemorySample;

use super::*;

const DEFAULT_EXECUTIONS: &[usize] = &[160, 192, 224, 256, 288, 320, 352, 357];
const BASELINE_SAMPLES: usize = DEFAULT_EXECUTIONS.len();
const ENGINEERING_GATE_BYTES: usize = 226_492_416;
const EXACT_NATIVE_PEAK_BYTES: usize = 441_080 * 1024;
const REQUIRED_SAVING_BYTES: usize = EXACT_NATIVE_PEAK_BYTES - 233_804 * 1024;
const RSS_ONLY_ENV: &str = "AOS_NIX_IMMUTABLE_COHORT_RSS_ONLY";
const PROJECTION_ENV: &str = "AOS_NIX_IMMUTABLE_COHORT_PROJECTION";
const BASELINE_RSS_ENV: &str = "AOS_NIX_IMMUTABLE_COHORT_BASELINE_RSS_BYTES";

#[derive(Debug)]
enum ImmutableCohortProbeMode {
    RssOnly,
    Projection {
        baseline_rss_bytes: [usize; BASELINE_SAMPLES],
    },
    Invalid(ImmutableCohortProbeConfigurationError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ImmutableCohortProbeConfigurationError {
    ConflictingModes,
    MissingBaseline,
    WrongBaselineCount,
    InvalidBaselineValue,
}

/// Per-evaluator state for the compile-time-only projection cadence.
#[derive(Debug)]
pub(super) struct ImmutableCohortProbe {
    mode: ImmutableCohortProbeMode,
    completion_count: usize,
    previous_fingerprints: HashMap<usize, u64>,
    previous_baseline_rss: Option<usize>,
    previous_projected_post_rss: Option<usize>,
    previous_installed_bytes: usize,
    previous_released_bytes: usize,
    previous_freezable_objects: usize,
    modeled_watermark_bytes: usize,
}

impl ImmutableCohortProbe {
    /// Builds an admitted probe only for the exact opt-in value.
    pub(super) fn from_env() -> Option<Self> {
        let rss_only = std::env::var(RSS_ONLY_ENV).as_deref() == Ok("1");
        let projection = std::env::var(PROJECTION_ENV).as_deref() == Ok("1");
        let mode = match (rss_only, projection) {
            (false, false) => return None,
            (true, false) => ImmutableCohortProbeMode::RssOnly,
            (false, true) => match std::env::var(BASELINE_RSS_ENV) {
                Ok(schedule) => match parse_baseline_rss_schedule(&schedule) {
                    Ok(baseline_rss_bytes) => {
                        ImmutableCohortProbeMode::Projection { baseline_rss_bytes }
                    }
                    Err(error) => ImmutableCohortProbeMode::Invalid(error),
                },
                Err(_) => ImmutableCohortProbeMode::Invalid(
                    ImmutableCohortProbeConfigurationError::MissingBaseline,
                ),
            },
            (true, true) => ImmutableCohortProbeMode::Invalid(
                ImmutableCohortProbeConfigurationError::ConflictingModes,
            ),
        };
        Some(Self::new(mode))
    }

    fn new(mode: ImmutableCohortProbeMode) -> Self {
        Self {
            mode,
            completion_count: 0,
            previous_fingerprints: HashMap::new(),
            previous_baseline_rss: None,
            previous_projected_post_rss: None,
            previous_installed_bytes: 0,
            previous_released_bytes: 0,
            previous_freezable_objects: 0,
            modeled_watermark_bytes: 0,
        }
    }

    fn selected_index(&self) -> Option<usize> {
        DEFAULT_EXECUTIONS
            .binary_search(&self.completion_count)
            .ok()
    }

    fn compare_fingerprints(&mut self, current: &[ImmutableCohortFingerprint]) -> (usize, usize) {
        let current_map = current
            .iter()
            .map(|entry| (entry.address, entry.fingerprint))
            .collect::<HashMap<_, _>>();
        let mutations = self
            .previous_fingerprints
            .iter()
            .filter(|(address, fingerprint)| {
                current_map
                    .get(address)
                    .is_some_and(|current| current != *fingerprint)
            })
            .count();
        let vanished = self
            .previous_fingerprints
            .keys()
            .filter(|address| !current_map.contains_key(address))
            .count();
        self.previous_fingerprints = current_map;
        (mutations, vanished)
    }

    fn cadence_projection(
        &mut self,
        baseline_rss: usize,
        projection: &ImmutableCohortProjection,
    ) -> (usize, usize) {
        let (projected_peak, projected_post) =
            match (self.previous_baseline_rss, self.previous_projected_post_rss) {
                (Some(previous_baseline), Some(previous_post)) => {
                    let modeled_pre =
                        apply_signed_delta(previous_post, baseline_rss, previous_baseline);
                    let installed_delta = projection
                        .installed_bytes()
                        .saturating_sub(self.previous_installed_bytes);
                    let released_delta = projection
                        .released_bytes()
                        .saturating_sub(self.previous_released_bytes);
                    let new_objects = projection
                        .freezable_objects
                        .saturating_sub(self.previous_freezable_objects);
                    let scratch_delta = new_objects.saturating_mul(12);
                    (
                        modeled_pre
                            .saturating_add(installed_delta)
                            .saturating_add(scratch_delta),
                        modeled_pre
                            .saturating_sub(released_delta)
                            .saturating_add(installed_delta),
                    )
                }
                _ => (
                    projection.projected_streaming_peak_rss(baseline_rss),
                    projection.projected_post_rss(baseline_rss),
                ),
            };
        self.previous_baseline_rss = Some(baseline_rss);
        self.previous_projected_post_rss = Some(projected_post);
        self.previous_installed_bytes = projection.installed_bytes();
        self.previous_released_bytes = projection.released_bytes();
        self.previous_freezable_objects = projection.freezable_objects;
        self.modeled_watermark_bytes = self.modeled_watermark_bytes.max(projected_peak);
        (projected_peak, projected_post)
    }
}

impl TreeWalk {
    /// Samples one selected successful final-config completion.
    pub(super) fn note_immutable_cohort_final_config_completion(&mut self) {
        let Some(mut probe) = self.immutable_cohort_projection_probe.take() else {
            return;
        };
        probe.completion_count = probe.completion_count.saturating_add(1);
        let Some(selected_index) = probe.selected_index() else {
            self.immutable_cohort_projection_probe = Some(probe);
            return;
        };
        let observed_rss = ProcessResidentMemorySample::current()
            .ok()
            .flatten()
            .map_or(0, ProcessResidentMemorySample::resident_bytes);
        let baseline_rss = match &probe.mode {
            ImmutableCohortProbeMode::RssOnly => {
                eprintln!(
                    "aos_nix_immutable_cohort_rss_baseline \
                     execution_count={} modules={} rss_bytes={}",
                    probe.completion_count,
                    self.modules.len(),
                    observed_rss,
                );
                self.immutable_cohort_projection_probe = Some(probe);
                return;
            }
            ImmutableCohortProbeMode::Invalid(error) => {
                eprintln!(
                    "aos_nix_immutable_cohort_projection_configuration_error \
                     execution_count={} error={error:?}",
                    probe.completion_count,
                );
                self.immutable_cohort_projection_probe = Some(probe);
                return;
            }
            ImmutableCohortProbeMode::Projection { baseline_rss_bytes } => {
                baseline_rss_bytes[selected_index]
            }
        };
        match self.heap.immutable_cohort_projection() {
            Ok(projection) => {
                let (mutations, vanished) = probe.compare_fingerprints(&projection.fingerprints);
                let (projected_peak, projected_post) =
                    probe.cadence_projection(baseline_rss, &projection);
                let projected_saving =
                    EXACT_NATIVE_PEAK_BYTES.saturating_sub(probe.modeled_watermark_bytes);
                eprintln!(
                    "aos_nix_immutable_cohort_projection \
                     execution_count={} modules={} baseline_rss_bytes={} \
                     observed_polluted_rss_bytes={} {} \
                     projected_epoch_peak_bytes={} projected_post_bytes={} \
                     modeled_watermark_bytes={} mutation_count={} vanished_count={} \
                     watermark_pass={} required_saving_bytes={} projected_saving_bytes={} \
                     saving_pass={}",
                    probe.completion_count,
                    self.modules.len(),
                    baseline_rss,
                    observed_rss,
                    projection,
                    projected_peak,
                    projected_post,
                    probe.modeled_watermark_bytes,
                    mutations,
                    vanished,
                    probe.modeled_watermark_bytes <= ENGINEERING_GATE_BYTES,
                    REQUIRED_SAVING_BYTES,
                    projected_saving,
                    projected_saving >= REQUIRED_SAVING_BYTES,
                );
            }
            Err(error) => eprintln!(
                "aos_nix_immutable_cohort_projection_error \
                 execution_count={} modules={} error={error:?}",
                probe.completion_count,
                self.modules.len(),
            ),
        }
        self.immutable_cohort_projection_probe = Some(probe);
    }
}

fn parse_baseline_rss_schedule(
    schedule: &str,
) -> Result<[usize; BASELINE_SAMPLES], ImmutableCohortProbeConfigurationError> {
    let values = schedule.split(',').collect::<Vec<_>>();
    if values.len() != BASELINE_SAMPLES {
        return Err(ImmutableCohortProbeConfigurationError::WrongBaselineCount);
    }
    let mut parsed = [0usize; BASELINE_SAMPLES];
    for (destination, value) in parsed.iter_mut().zip(values) {
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(ImmutableCohortProbeConfigurationError::InvalidBaselineValue);
        }
        *destination = value
            .parse()
            .map_err(|_| ImmutableCohortProbeConfigurationError::InvalidBaselineValue)?;
        if *destination == 0 {
            return Err(ImmutableCohortProbeConfigurationError::InvalidBaselineValue);
        }
    }
    Ok(parsed)
}

fn apply_signed_delta(base: usize, current: usize, previous: usize) -> usize {
    if current >= previous {
        base.saturating_add(current - previous)
    } else {
        base.saturating_sub(previous - current)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_schedule_selects_only_requested_completions() {
        let mut probe = ImmutableCohortProbe::new(ImmutableCohortProbeMode::RssOnly);
        probe.completion_count = 159;
        assert_eq!(probe.selected_index(), None);
        probe.completion_count = 160;
        assert_eq!(probe.selected_index(), Some(0));
        probe.completion_count = 192;
        assert_eq!(probe.selected_index(), Some(1));
    }

    #[test]
    fn fingerprint_comparison_reports_mutation_and_disappearance() {
        let mut probe = ImmutableCohortProbe::new(ImmutableCohortProbeMode::Projection {
            baseline_rss_bytes: [1; BASELINE_SAMPLES],
        });
        probe.previous_fingerprints.insert(10, 1);
        probe.previous_fingerprints.insert(20, 2);
        let current = [ImmutableCohortFingerprint {
            address: 10,
            fingerprint: 3,
        }];
        assert_eq!(probe.compare_fingerprints(&current), (1, 1));
    }

    #[test]
    fn cadence_charges_only_new_installed_state_after_first_epoch() {
        let mut probe = ImmutableCohortProbe::new(ImmutableCohortProbeMode::Projection {
            baseline_rss_bytes: [1; BASELINE_SAMPLES],
        });
        let first = ImmutableCohortProjection {
            freezable_objects: 10,
            compact_bytes: 100,
            handle_table_bytes: 80,
            releasable_source_page_bytes: 400,
            ..ImmutableCohortProjection::default()
        };
        let (_, first_post) = probe.cadence_projection(1_000, &first);
        let second = ImmutableCohortProjection {
            freezable_objects: 12,
            compact_bytes: 120,
            handle_table_bytes: 96,
            releasable_source_page_bytes: 500,
            ..ImmutableCohortProjection::default()
        };
        let (second_peak, second_post) = probe.cadence_projection(1_100, &second);
        assert_eq!(first_post, 780);
        assert_eq!(second_peak, 940);
        assert_eq!(second_post, 816);
    }

    #[test]
    fn signed_rss_delta_tracks_decreases() {
        assert_eq!(apply_signed_delta(900, 800, 1_000), 700);
    }

    #[test]
    fn baseline_schedule_requires_exact_positive_decimal_values() {
        let parsed = parse_baseline_rss_schedule("1,2,3,4,5,6,7,8")
            .expect("eight positive decimal values parse");
        assert_eq!(parsed, [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(
            parse_baseline_rss_schedule("1,2,3,4,5,6,7"),
            Err(ImmutableCohortProbeConfigurationError::WrongBaselineCount)
        );
        assert_eq!(
            parse_baseline_rss_schedule("1,2,3,4,5,6,7, 8"),
            Err(ImmutableCohortProbeConfigurationError::InvalidBaselineValue)
        );
        assert_eq!(
            parse_baseline_rss_schedule("1,2,3,4,5,6,7,0"),
            Err(ImmutableCohortProbeConfigurationError::InvalidBaselineValue)
        );
    }
}
