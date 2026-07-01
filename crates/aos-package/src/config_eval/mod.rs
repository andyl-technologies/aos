//! The RFC-0011 resolve↔eval fixpoint driver (P1, on-host config eval).
//!
//! Stock Nix gives no read-access instrumentation, so the set of config
//! providers a host needs cannot be statically closed: it is *discovered* by
//! evaluating the module set, observing what is missing, fetching the named
//! provider's `config` output, and re-evaluating until the eval succeeds or a
//! terminal state is reached. [`run_fixpoint`] is that deterministic state
//! machine; it is the driver *around* the existing closure resolver
//! ([`crate::resolve`]).
//!
//! # Module map
//!
//! - [`classify`] — the fragile string parse of stock-Nix throw strings into
//!   the [`EvalClass`] seam (build-spec §2). P2 aos-nix replaces exactly this.
//! - [`stock`] — the production [`NixEvaluator`] that renders `entry.nix`,
//!   shells out to `nix eval --option restrict-eval true
//!   --option allow-import-from-derivation false` (NOT `--pure-eval`, which
//!   would forbid importing the base-lib by store path), and classifies the
//!   result, plus the registry-backed [`ConfigOutputFetcher`]. Builder-gated:
//!   it requires a real
//!   stock-nix and registry, so it is unit-tested only for `entry.nix`
//!   rendering.
//!
//! # The seam
//!
//! Everything the P2 evaluator must keep stable is `eval(working_set, host_nix,
//! base_lib) -> Result<EvalClass>`. The resolver, the registry index, the fetch
//! order (config output first), the `module_abi` gate, and the manifest
//! contract are identical on both evaluators; swapping P1↔P2 changes only how
//! [`EvalClass`] is produced.
//!
//! # Failure-safe
//!
//! The fixpoint produces *only* a manifest and never activates. Every terminal
//! state — a [`FixpointError`] or non-convergence at the iteration cap — is a
//! clean no-op on the live system: no generation exists until a downstream
//! service consumes a returned manifest.

pub mod classify;
pub mod diagnostics;
pub mod dry_run;
pub mod materialize;
pub mod stock;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

pub use classify::{ConflictDef, EvalClass, KillReason, MissingOption, MissingOptionKind};

use crate::resolve::{GatedConfigModule, enforce_module_abi_compat, select_index_provider};
use crate::types::{ModuleAbiCompat, ProvidesIndex, option_path_root};

/// Absolute ceiling on re-evals, so a pathological registry cannot make the
/// loop unbounded (build-spec §5).
pub const ITER_CAP_CEILING: u32 = 64;

/// Slack added to the reachable-provider count when deriving the iteration cap.
const ITER_CAP_SLACK: u32 = 8;

// ---------------------------------------------------------------------------
// Working set
// ---------------------------------------------------------------------------

/// One package in the fixpoint working set.
///
/// The seed set is supplied by the caller from the host's desired packages;
/// fetched providers are appended as the loop discovers missing options. A
/// member that carries config-module metadata is gated against the running
/// image's `module_abi` before it can enter `entry.nix`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkingSetMember {
    /// Package name.
    pub package: String,
    /// Package version, when known.
    pub version: Option<String>,
    /// Store path of the package's `config` output (its config-only module),
    /// when it ships one. This is the only thing the eval reads.
    pub config_output: Option<String>,
    /// The member's declared base-lib ABI band, when it ships a config module.
    pub module_abi_compat: Option<ModuleAbiCompat>,
}

impl WorkingSetMember {
    /// Builds a bare seed member with no config-module metadata.
    pub fn seed(package: impl Into<String>) -> Self {
        Self {
            package: package.into(),
            version: None,
            config_output: None,
            module_abi_compat: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Inputs / outputs
// ---------------------------------------------------------------------------

/// Immutable inputs for one `switch` (build-spec §1).
#[derive(Debug, Clone)]
pub struct FixpointInputs {
    /// The verified, provenance-stamped leaf `host.nix` store path.
    pub host_nix: PathBuf,
    /// The in-image, ABI-pinned module library.
    pub base_lib: PathBuf,
    /// Packages explicitly installed (`desired.toml`): the starting working set.
    pub seed_set: Vec<WorkingSetMember>,
    /// The running image's base-lib ABI (`K`).
    pub module_abi: u32,
    /// Optional override for the iteration cap; otherwise derived from the index.
    pub iter_cap: Option<u32>,
}

/// One step of the causal chain, recorded for the non-convergence dump.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IterRecord {
    /// 0-based iteration at which the provider was added.
    pub iter: u32,
    /// The missing option that triggered the fetch (full leaf or root).
    pub missing_path: String,
    /// Whether the trigger was a write (Case A) or a read (Case B).
    pub kind: MissingOptionKind,
    /// The provider package added to the working set.
    pub provider_added: String,
    /// The reader/writer locus, when stock Nix reported it.
    pub read_by: Option<String>,
}

/// A converged fixpoint: the rendered manifest plus its provenance.
#[derive(Debug, Clone)]
pub struct FixpointOutcome {
    /// The JSON manifest text the final eval produced.
    pub manifest: String,
    /// The converged working set (seed plus every fetched provider).
    pub working_set: Vec<WorkingSetMember>,
    /// The causal chain of provider additions.
    pub trace: Vec<IterRecord>,
    /// Number of re-eval iterations performed.
    pub iterations: u32,
}

// ---------------------------------------------------------------------------
// Terminal errors
// ---------------------------------------------------------------------------

/// A terminal fixpoint failure. Every variant is a clean no-op on the live
/// system (build-spec §1).
#[derive(Debug)]
pub enum FixpointError {
    /// A missing option whose root/path the registry does not provide at all.
    NoProvider {
        /// The unresolved option path or root.
        path: String,
        /// The reader/writer locus, when known.
        read_by: Option<String>,
    },
    /// A missing option whose providers all exclude the running `module_abi`.
    AbiMismatch {
        /// The unresolved option path or root.
        path: String,
        /// The running image ABI the providers failed to admit.
        want: u32,
    },
    /// A seed config module excludes the running `module_abi` (pre-eval gate).
    SeedAbiMismatch(String),
    /// More than one owner of a shared root survived the ABI filter.
    AmbiguousProvider {
        /// The option path or root with multiple compatible owners.
        path: String,
    },
    /// A provider is already present yet the same option stays missing —
    /// fetching cannot help (a read cycle's terminal frame).
    Unsatisfiable {
        /// The still-missing option path or root.
        path: String,
        /// The provider already in the working set.
        provider: String,
    },
    /// A *declared* option was left undefined with no default (`:744`).
    UndefinedOption {
        /// The declared-but-unset option path.
        path: String,
        /// The defining locus, when reported.
        file: Option<String>,
    },
    /// A scalar/type conflict between definitions.
    Conflict {
        /// Every conflicting definition stock Nix listed.
        defs: Vec<ConflictDef>,
    },
    /// A forced assertion failed.
    AssertionFailed {
        /// The assertion message as authored.
        msg: String,
        /// The defining locus, when reported.
        file: Option<String>,
    },
    /// The eval subprocess was OOM-/timeout-killed by its transient scope.
    EvalKilled {
        /// Why the subprocess was killed.
        reason: KillReason,
    },
    /// An opaque Nix failure that matched no known pattern.
    EvalError {
        /// The raw stderr, preserved for the operator.
        stderr: String,
    },
    /// Fetching a selected provider's `config` output failed terminally.
    Fetch {
        /// The provider whose fetch failed.
        provider: String,
        /// The underlying fetch error.
        source: anyhow::Error,
    },
    /// The loop did not converge within the iteration cap.
    NonConvergence {
        /// The causal chain, for the operator dump.
        trace: Vec<IterRecord>,
        /// The cap that was hit.
        iterations: u32,
    },
}

impl std::fmt::Display for FixpointError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FixpointError::NoProvider { path, read_by } => {
                write!(f, "no registry provider declares '{path}'")?;
                if let Some(loc) = read_by {
                    write!(f, " (read by {loc})")?;
                }
                Ok(())
            }
            FixpointError::AbiMismatch { path, want } => write!(
                f,
                "every provider of '{path}' is incompatible with image module_abi {want}"
            ),
            FixpointError::SeedAbiMismatch(msg) => f.write_str(msg),
            FixpointError::AmbiguousProvider { path } => write!(
                f,
                "option '{path}' has more than one compatible owner; owned-root exclusivity requires exactly one"
            ),
            FixpointError::Unsatisfiable { path, provider } => write!(
                f,
                "'{path}' is still missing after fetching '{provider}'; fetching cannot satisfy it (read cycle)"
            ),
            FixpointError::UndefinedOption { path, file } => {
                write!(f, "the option '{path}' is declared but left undefined")?;
                if let Some(file) = file {
                    write!(f, " (at {file})")?;
                }
                Ok(())
            }
            FixpointError::Conflict { defs } => {
                write!(f, "conflicting definitions:")?;
                for def in defs {
                    let value = def.value.as_deref().unwrap_or("?");
                    let file = def.file.as_deref().unwrap_or("?");
                    write!(f, "\n  - '{value}' (defined in {file})")?;
                }
                Ok(())
            }
            FixpointError::AssertionFailed { msg, file } => {
                write!(f, "assertion failed: {msg}")?;
                if let Some(file) = file {
                    write!(f, " (at {file})")?;
                }
                Ok(())
            }
            FixpointError::EvalKilled { reason } => write!(f, "config eval killed: {reason}"),
            FixpointError::EvalError { stderr } => write!(f, "config eval failed:\n{stderr}"),
            FixpointError::Fetch { provider, source } => {
                write!(f, "fetching config output for '{provider}' failed: {source}")
            }
            FixpointError::NonConvergence { trace, iterations } => {
                write!(f, "{}", render_trace(trace, *iterations))
            }
        }
    }
}

impl std::error::Error for FixpointError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            FixpointError::Fetch { source, .. } => Some(source.as_ref()),
            _ => None,
        }
    }
}

/// Render the build-spec §5 non-convergence dump from the causal chain.
fn render_trace(trace: &[IterRecord], iterations: u32) -> String {
    let mut out = format!("config eval did not converge after {iterations} iterations:\n");
    for record in trace {
        let loc = record
            .read_by
            .as_deref()
            .map(|l| format!(" [{l}]"))
            .unwrap_or_default();
        out.push_str(&format!(
            "  iter {}: {} '{}' ({}) -> +{}{}\n",
            record.iter,
            record.kind.label(),
            record.missing_path,
            record.kind.label(),
            record.provider_added,
            loc,
        ));
    }
    out
}

// ---------------------------------------------------------------------------
// Injected collaborators
// ---------------------------------------------------------------------------

/// One eval attempt's inputs, handed to a [`NixEvaluator`].
#[derive(Debug)]
pub struct EvalAttempt<'a> {
    /// The verified leaf `host.nix`, passed as an operator-provenance module.
    pub host_nix: &'a Path,
    /// The in-image module library.
    pub base_lib: &'a Path,
    /// The current working set rendered into `entry.nix`.
    pub working_set: &'a [WorkingSetMember],
    /// 0-based iteration counter.
    pub iteration: u32,
}

/// The evaluator seam: render the working set and classify the eval result.
///
/// The P1 implementation ([`stock::StockNixEvaluator`]) renders `entry.nix`,
/// runs a cold stock-Nix subprocess, and parses stderr via [`classify`]. The P2
/// aos-nix implementation produces the same [`EvalClass`] from structured
/// engine errors. Tests inject a scripted mock.
pub trait NixEvaluator {
    /// Evaluate `attempt` and return its classified outcome.
    ///
    /// # Errors
    ///
    /// Returns an error only when the evaluator cannot be *driven* at all (e.g.
    /// the subprocess could not be spawned). Eval-level failures (missing
    /// options, conflicts, kills) are reported in-band as [`EvalClass`].
    fn evaluate(&self, attempt: &EvalAttempt<'_>) -> Result<EvalClass>;
}

/// A provider the driver selected from the index and is about to fetch.
#[derive(Debug, Clone, Copy)]
pub struct SelectedProvider<'a> {
    /// Provider package name.
    pub package: &'a str,
    /// Provider package version.
    pub version: &'a str,
    /// Target platform.
    pub platform: &'a str,
    /// Store path of the `config` output to fetch.
    pub config_output: &'a str,
}

/// The fetch seam: download a selected provider's `config` output NAR.
///
/// The driver fetches the `config` output **before** any `out` closure
/// (build-spec §4): the next eval reads only the config-only module, and the
/// binary closure is needed solely if the provider survives into the converged
/// set. Tests inject a recording mock.
pub trait ConfigOutputFetcher {
    /// Fetch and verify `provider`'s `config` output into the local store.
    ///
    /// # Errors
    ///
    /// Returns an error on a terminal fetch failure (registry unreachable,
    /// unsigned, hash mismatch); the driver maps it to [`FixpointError::Fetch`].
    fn fetch_config_output(&self, provider: &SelectedProvider<'_>) -> Result<()>;
}

// ---------------------------------------------------------------------------
// The fixpoint
// ---------------------------------------------------------------------------

/// Drive stock-Nix `evalModules` to a complete configuration (build-spec §1).
///
/// The loop renders the current `working_set` into `entry.nix`, evaluates it,
/// and on a missing-option signal selects the owning provider from `index`
/// (ABI-filtered), fetches its `config` output, and re-evaluates. `working_set`
/// is append-only over the finite package universe, so the loop terminates at
/// or before the iteration cap.
///
/// Before iteration 0 every seed that carries config-module metadata is gated
/// against `inputs.module_abi`; an incompatible seed is a terminal
/// [`FixpointError::SeedAbiMismatch`] before any eval runs. Each fetched
/// provider is likewise gated before it enters `entry.nix`.
///
/// # Errors
///
/// Returns a [`FixpointError`] for every terminal state (no provider, ABI
/// mismatch, conflict, assertion, kill, opaque eval error, fetch failure) and
/// [`FixpointError::NonConvergence`] at the iteration cap. Every terminal state
/// is a clean no-op: no manifest is emitted, so nothing downstream activates.
pub fn run_fixpoint<E, F>(
    inputs: &FixpointInputs,
    index: &ProvidesIndex,
    evaluator: &E,
    fetcher: &F,
) -> std::result::Result<FixpointOutcome, FixpointError>
where
    E: NixEvaluator,
    F: ConfigOutputFetcher,
{
    // Pre-eval gate (build-spec §6): refuse an ABI-incompatible seed before any
    // eval. Wires CS3's `enforce_module_abi_compat` into the live path.
    gate_seeds(&inputs.seed_set, inputs.module_abi)?;

    let mut working_set = inputs.seed_set.clone();
    // The no-progress guard tracks packages whose CONFIG MODULE is actually
    // loaded (`config_output` present), NOT every seed name. A bare seed (a
    // desired package with no config module yet) must remain fetchable — if the
    // host references its root, the loop fetches its config output. Seeding the
    // guard with bare names would wedge such a package to `Unsatisfiable`.
    let mut fetched: BTreeSet<String> = working_set
        .iter()
        .filter(|m| m.config_output.is_some())
        .map(|m| m.package.clone())
        .collect();
    let mut trace: Vec<IterRecord> = Vec::new();
    let cap = inputs.iter_cap.unwrap_or_else(|| derive_iter_cap(index));

    let mut iter: u32 = 0;
    loop {
        if iter >= cap {
            return Err(FixpointError::NonConvergence {
                trace,
                iterations: iter,
            });
        }

        let attempt = EvalAttempt {
            host_nix: &inputs.host_nix,
            base_lib: &inputs.base_lib,
            working_set: &working_set,
            iteration: iter,
        };
        let class = evaluator
            .evaluate(&attempt)
            .map_err(|e| FixpointError::EvalError {
                stderr: format!("{e:#}"),
            })?;

        match class {
            EvalClass::Manifest(manifest) => {
                return Ok(FixpointOutcome {
                    manifest,
                    working_set,
                    trace,
                    iterations: iter,
                });
            }
            EvalClass::Missing(missing) => {
                let selection = select_first_resolvable(&missing, index, inputs.module_abi)?;

                // The provider's config module is already loaded yet the same
                // option is still missing — fetching cannot fix it (build-spec
                // §5 read cycle / bad config module). This is the real
                // no-progress condition.
                if fetched.contains(&selection.package) {
                    return Err(FixpointError::Unsatisfiable {
                        path: selection.missing_path.clone(),
                        provider: selection.package,
                    });
                }

                // Gate the newly-selected provider before it enters entry.nix.
                let gate = GatedConfigModule {
                    package: &selection.package,
                    version: &selection.version,
                    module_abi_compat: selection.module_abi_compat,
                };
                enforce_module_abi_compat(&[gate], inputs.module_abi).map_err(|_| {
                    FixpointError::AbiMismatch {
                        path: selection.missing_path.clone(),
                        want: inputs.module_abi,
                    }
                })?;

                // Config output FIRST (build-spec §4).
                let provider = SelectedProvider {
                    package: &selection.package,
                    version: &selection.version,
                    platform: &selection.platform,
                    config_output: &selection.config_output,
                };
                fetcher
                    .fetch_config_output(&provider)
                    .map_err(|source| FixpointError::Fetch {
                        provider: selection.package.clone(),
                        source,
                    })?;

                fetched.insert(selection.package.clone());
                working_set.push(WorkingSetMember {
                    package: selection.package.clone(),
                    version: Some(selection.version.clone()),
                    config_output: Some(selection.config_output.clone()),
                    module_abi_compat: Some(selection.module_abi_compat),
                });
                trace.push(IterRecord {
                    iter,
                    missing_path: selection.missing_path,
                    kind: selection.kind,
                    provider_added: selection.package,
                    read_by: selection.read_by,
                });
                iter += 1;
            }
            EvalClass::UndefinedOption { path, file } => {
                return Err(FixpointError::UndefinedOption { path, file });
            }
            EvalClass::Conflict { defs } => return Err(FixpointError::Conflict { defs }),
            EvalClass::Assertion { msg, file } => {
                return Err(FixpointError::AssertionFailed { msg, file });
            }
            EvalClass::Killed(reason) => return Err(FixpointError::EvalKilled { reason }),
            EvalClass::Other { stderr } => return Err(FixpointError::EvalError { stderr }),
        }
    }
}

/// Gate every seed that carries config-module metadata (build-spec §6).
fn gate_seeds(seeds: &[WorkingSetMember], image_abi: u32) -> std::result::Result<(), FixpointError> {
    let gates: Vec<GatedConfigModule<'_>> = seeds
        .iter()
        .filter_map(|m| {
            m.module_abi_compat.map(|compat| GatedConfigModule {
                package: m.package.as_str(),
                version: m.version.as_deref().unwrap_or(""),
                module_abi_compat: compat,
            })
        })
        .collect();
    enforce_module_abi_compat(&gates, image_abi)
        .map_err(|e| FixpointError::SeedAbiMismatch(format!("{e:#}")))
}

/// Derive the iteration cap: reachable providers + slack, capped at the ceiling.
fn derive_iter_cap(index: &ProvidesIndex) -> u32 {
    let providers: BTreeSet<(&str, &str)> = index
        .options
        .values()
        .flat_map(|entries| entries.iter())
        .map(|e| (e.package.as_str(), e.version.as_str()))
        .collect();
    let count = u32::try_from(providers.len()).unwrap_or(ITER_CAP_CEILING);
    count.saturating_add(ITER_CAP_SLACK).min(ITER_CAP_CEILING)
}

/// A concrete provider choice the driver resolved from a missing-option signal.
struct Selection {
    package: String,
    version: String,
    platform: String,
    config_output: String,
    module_abi_compat: ModuleAbiCompat,
    missing_path: String,
    kind: MissingOptionKind,
    read_by: Option<String>,
}

/// Pick the first missing option that resolves to a provider, recording the
/// terminal error if none do (build-spec §2: "picks the first whose lookup
/// resolves").
fn select_first_resolvable(
    missing: &[MissingOption],
    index: &ProvidesIndex,
    abi: u32,
) -> std::result::Result<Selection, FixpointError> {
    let mut deferred: Option<FixpointError> = None;
    for item in missing {
        match resolve_one(item, index, abi) {
            Ok(selection) => return Ok(selection),
            Err(err) => {
                // Keep the most informative terminal error: an ABI mismatch or
                // ambiguity outranks a plain "no provider", which is the
                // fallback when nothing resolved.
                if deferred
                    .as_ref()
                    .map(|d| matches!(d, FixpointError::NoProvider { .. }))
                    .unwrap_or(true)
                {
                    deferred = Some(err);
                }
            }
        }
    }
    Err(deferred.unwrap_or_else(|| FixpointError::NoProvider {
        path: missing
            .first()
            .map(|m| m.path.clone())
            .unwrap_or_default(),
        read_by: missing.first().and_then(|m| m.read_by.clone()),
    }))
}

/// Resolve a single missing option to a provider, using the lookup shape its
/// [`MissingOptionKind`] dictates (build-spec §4).
fn resolve_one(
    item: &MissingOption,
    index: &ProvidesIndex,
    abi: u32,
) -> std::result::Result<Selection, FixpointError> {
    let entry = match item.kind {
        // Case A: exact full-path lookup with owned-root exclusivity, wiring
        // CS3's `select_index_provider` into the live path.
        MissingOptionKind::UndeclaredWrite => {
            let has_any = index.options.contains_key(&item.path);
            let compatible = !index.providers_for(&item.path, abi).is_empty();
            if !compatible {
                return Err(if has_any {
                    FixpointError::AbiMismatch {
                        path: item.path.clone(),
                        want: abi,
                    }
                } else {
                    FixpointError::NoProvider {
                        path: item.path.clone(),
                        read_by: item.read_by.clone(),
                    }
                });
            }
            select_index_provider(index, &item.path, abi).map_err(|_| {
                FixpointError::AmbiguousProvider {
                    path: item.path.clone(),
                }
            })?
        }
        // Case B: first-segment lookup, owned roots are exclusive.
        MissingOptionKind::AbsentRootRead => {
            let root = option_path_root(&item.path);
            let candidates = index.providers_for_root(root, abi);
            if candidates.is_empty() {
                return Err(if index.declares_root(root) {
                    FixpointError::AbiMismatch {
                        path: item.path.clone(),
                        want: abi,
                    }
                } else {
                    FixpointError::NoProvider {
                        path: item.path.clone(),
                        read_by: item.read_by.clone(),
                    }
                });
            }
            let owners: Vec<_> = candidates.iter().filter(|e| e.owner).collect();
            match owners.as_slice() {
                [owner] => owner,
                [] => candidates[0],
                _ => {
                    return Err(FixpointError::AmbiguousProvider {
                        path: item.path.clone(),
                    });
                }
            }
        }
    };

    Ok(Selection {
        package: entry.package.clone(),
        version: entry.version.clone(),
        platform: entry.platform.clone(),
        config_output: entry.config_output.clone(),
        module_abi_compat: entry.module_abi_compat,
        missing_path: item.path.clone(),
        kind: item.kind,
        read_by: item.read_by.clone(),
    })
}

// ---------------------------------------------------------------------------
// CLI driver (`apm __eval` / `aos config eval`)
// ---------------------------------------------------------------------------

/// Parameters for the on-host config-eval command.
#[derive(Debug, Clone)]
pub struct EvalCommand {
    /// The verified leaf `host.nix` store path.
    pub host_nix: PathBuf,
    /// The in-image module library store path.
    pub base_lib: PathBuf,
    /// The registry `provides` index (`index/provides.json`); empty when absent.
    pub index: Option<PathBuf>,
    /// Optional `desired.toml` whose `packages` seed the working set.
    pub desired: Option<PathBuf>,
    /// The running image's base-lib ABI.
    pub module_abi: u32,
    /// Where to write the converged manifest (only on success).
    pub out: PathBuf,
    /// The eval root that holds `entry.nix` (`-I` search path).
    pub eval_root: PathBuf,
    /// Verbosity forwarded to `nix`.
    pub verbose: u8,
    /// Operator trust-anchor directories holding `trusted-config-keys.d/<op>.pub`
    /// (build-spec §3.2). [`run_eval_command`] verifies the `host.nix` SSHSIG
    /// against these anchors **before** the fixpoint drives — the stage-2 trust
    /// gate that turns CS8's untrusted transport into a trusted eval input.
    pub trusted_config_keys_dirs: Vec<PathBuf>,

    /// **Off-host escape hatch only.** When `false` (the default and the only
    /// safe on-host value), the trust gate is ALWAYS enforced: an empty
    /// `trusted_config_keys_dirs`, a missing anchor, or a missing/bad signature
    /// fails closed (no manifest). It is `true` only for off-host CI / `--dry-run`
    /// where `host.nix` is a trusted checked-out fixture, never user-data. This
    /// is a distinct, explicit flag precisely so the absence of an anchor dir can
    /// never silently fail OPEN on the boot path.
    pub allow_unsigned_host_nix: bool,
}

/// Run the on-host fixpoint with the production stock-Nix evaluator and fetcher.
///
/// Loads the registry index and seed set from disk, drives [`run_fixpoint`], and
/// — **only on convergence** — writes the manifest to [`EvalCommand::out`]. Any
/// terminal failure prints a legible diagnostic and returns an error *without*
/// writing a manifest, so the downstream `ConditionPathExists` guard makes the
/// install step a no-op and the box stays live on the gen-0 seed.
///
/// # Errors
///
/// Returns an error when the index/desired files cannot be read or parsed, when
/// the fixpoint reaches a terminal state, or when the manifest cannot be
/// written. The caller (the hidden `apm __eval` subcommand) maps this to a
/// non-zero exit; the service treats it as best-effort.
pub fn run_eval_command(cmd: &EvalCommand) -> Result<()> {
    // Stage-2 trust gate (build-spec §3): an unsigned, badly-signed, or
    // untrusted-key host.nix produces NO manifest. This runs BEFORE the fixpoint
    // drives, so a failed authenticity check is a clean no-op on the live
    // system — the box stays on the prior generation. The gate is the trust seam
    // CS8's transport-only metadata agent deferred to stage-2.
    // Enforced BY DEFAULT. Skipped only with the explicit off-host escape hatch,
    // so the absence of an anchor dir on the boot path fails CLOSED (an empty
    // dir set makes authenticate_host_nix_file return NoTrustedKeys) rather than
    // silently fails open.
    if cmd.allow_unsigned_host_nix {
        eprintln!(
            "WARNING: host.nix authenticity gate DISABLED (--allow-unsigned-host-nix); \
             off-host/CI mode only — never use on a host consuming user-data"
        );
    } else {
        match crate::config_trust::authenticate_host_nix_file(
            &cmd.host_nix,
            &cmd.trusted_config_keys_dirs,
        ) {
            Ok(trust) => {
                eprintln!(
                    "host.nix authenticated (operator '{}', key {})",
                    trust.operator_id, trust.operator_key
                );
            }
            Err(err) => {
                anyhow::bail!(
                    "host.nix failed the stage-2 authenticity gate: {err}; no manifest emitted"
                );
            }
        }
    }

    let index = match &cmd.index {
        Some(path) if path.exists() => {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("reading provides index {}", path.display()))?;
            serde_json::from_str::<ProvidesIndex>(&text)
                .with_context(|| format!("parsing provides index {}", path.display()))?
        }
        _ => ProvidesIndex::empty(),
    };

    let seed_set = load_seed_set(cmd.desired.as_deref())?;

    let inputs = FixpointInputs {
        host_nix: cmd.host_nix.clone(),
        base_lib: cmd.base_lib.clone(),
        seed_set,
        module_abi: cmd.module_abi,
        iter_cap: None,
    };

    let evaluator = stock::StockNixEvaluator::new(cmd.eval_root.clone(), cmd.verbose);
    let fetcher = stock::SubstituterFetcher::new(cmd.verbose);

    match run_fixpoint(&inputs, &index, &evaluator, &fetcher) {
        Ok(outcome) => {
            if let Some(parent) = cmd.out.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
            std::fs::write(&cmd.out, outcome.manifest.as_bytes())
                .with_context(|| format!("writing manifest {}", cmd.out.display()))?;
            eprintln!(
                "config eval converged after {} iteration(s); manifest written to {}",
                outcome.iterations,
                cmd.out.display()
            );
            Ok(())
        }
        Err(err) => {
            // Failure-safe: no manifest is emitted, so nothing downstream
            // activates. Surface the terminal diagnostic for the operator.
            anyhow::bail!("config eval did not produce a manifest: {err}");
        }
    }
}

/// Re-evaluate a config-generation across an ABI boundary from its retained
/// inputs (RFC-0011 build-spec §6, the cross-ABI rollback path).
///
/// When a config-gen's `module_abi_pinned` differs from the running image's
/// `module_abi`, direct re-activation is refused and the generation is instead
/// **re-evaluated** — never blindly replayed — against the rolled-back image's
/// evaluator. This entrypoint maps the
/// [`CrossAbiReEvalInputs`](crate::types::CrossAbiReEvalInputs) the rollback
/// path looked up (the `host.nix` content-pin, the running base lib, the target
/// ABI) into an [`EvalCommand`] and drives the existing fixpoint via
/// [`run_eval_command`]. Because eval is pure and content-addressed, the
/// recomputation is deterministic and usually cache-hits.
///
/// `running_base_lib` is the rolled-back image's base-lib store path (the ABI
/// artifact retained on `/var` by the `image-gen-N/baselib/<module_abi>` root).
/// `index`, `desired`, `eval_root`, and `out` mirror [`EvalCommand`]; the seed
/// set and instance facts are resolved exactly as a normal eval. The §3 pre-eval
/// ABI gate still applies inside [`run_fixpoint`], so a config module
/// incompatible with the rolled-back ABI is refused fail-closed and the old gen
/// stays live.
///
/// # Errors
///
/// Returns an error when the underlying [`run_eval_command`] fails — the index
/// or seed set cannot be read, the fixpoint reaches a terminal state (including
/// the pre-eval ABI gate refusing a module against `to_module_abi`), or the
/// manifest cannot be written. No manifest is emitted on failure, so nothing
/// downstream activates and the old config-gen stays live.
pub fn reeval_cross_abi(
    retained: &crate::types::CrossAbiReEvalInputs,
    running_base_lib: &Path,
    index: Option<PathBuf>,
    desired: Option<PathBuf>,
    eval_root: PathBuf,
    out: PathBuf,
    verbose: u8,
) -> Result<()> {
    let cmd = EvalCommand {
        // The content-pinned host.nix the rolled-back-to config-gen recorded —
        // fed back verbatim so re-eval reproduces the intended config (OQ5).
        host_nix: PathBuf::from(&retained.host_nix_ref),
        base_lib: running_base_lib.to_path_buf(),
        index,
        desired,
        // Re-eval is pinned to the *running* (rolled-back) image's ABI.
        module_abi: retained.to_module_abi,
        out,
        eval_root,
        verbose,
        // The content-pinned host.nix was already authenticated when its
        // config-gen was first committed (build-spec §3.5); the binding-of-record
        // is the content hash fed back here (an immutable store path), so re-eval
        // intentionally bypasses the signature gate. This is the one legitimate
        // on-box bypass — a previously-trusted, content-addressed artifact, NOT
        // fresh user-data — so it sets the explicit flag rather than relying on
        // an empty anchor dir (which now fails closed).
        trusted_config_keys_dirs: Vec::new(),
        allow_unsigned_host_nix: true,
    };
    run_eval_command(&cmd)
}

/// Load seed package names from a `desired.toml`, as bare working-set members.
///
/// Only the top-level `packages` array is read; seed config-module metadata
/// (config outputs, ABI bands) is discovered by the loop, so seeds carry no
/// config output here.
fn load_seed_set(desired: Option<&Path>) -> Result<Vec<WorkingSetMember>> {
    let Some(path) = desired else {
        return Ok(Vec::new());
    };
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading desired packages {}", path.display()))?;
    let doc: toml::Value =
        toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    let names = doc
        .as_table()
        .and_then(|table| table.get("packages"))
        .and_then(|packages| packages.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|entry| entry.as_str())
                .map(WorkingSetMember::seed)
                .collect()
        })
        .unwrap_or_default();
    Ok(names)
}

#[cfg(test)]
mod tests;
