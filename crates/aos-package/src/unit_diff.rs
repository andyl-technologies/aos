// SPDX-License-Identifier: MIT
//
//! Live-vs-candidate systemd unit diff engine for the activation reconcile split.
//!
//! Heavily ported from nixpkgs'
//! `nixos/modules/system/activation/switch-to-configuration-ng/src/main.rs`
//! (switch-to-configuration-ng, "STC").
//!   Upstream rev: 6c9a78c09ff4d6c21d0319114873508a6ec01655
//!
//! Portions © 2003-2026 Eelco Dolstra and the Nixpkgs/NixOS contributors.
//! Used under the MIT license; see nixpkgs' COPYING file for the full text.
//!
//! What is ported (per-function `cribbed from …` citations below match the
//! style the sibling `aos-systemd` crate already uses):
//!   - the systemd-INI parser, incl. the empty-value-clears semantic
//!     (STC `parse_systemd_ini`, `main.rs:344-411`);
//!   - the ignored `[Unit]` key list stripped before fingerprinting
//!     (STC `main.rs:503-520`);
//!   - the per-unit-type restart/reload/stop policy and the `X-*` contract
//!     reading (STC `compare_units` / `handle_modified_unit`,
//!     `main.rs:488-755`);
//!   - the socket-activation service→sockets mapping (STC `main.rs:803-816`).
//!
//! AOS adaptations:
//!   - The diff compares two *on-disk merged `/etc` views* (the live overlay
//!     vs the candidate overlay built by the activate script), not systemd's
//!     in-memory unit set. There is no `Manager.ListUnitFiles` round-trip.
//!   - Fingerprints use `djb2_hash` (shared with `sysroot`), not xxhash64:
//!     the hash is only ever compared live-vs-candidate inside one process,
//!     so any deterministic hash works and we avoid a new crate dependency.
//!   - `X-Reload-Triggers` is a plain space-joined path list (AOS renders it
//!     that way; upstream points it at a `writeText` store path). Its content
//!     is folded into the unit's *effective* fingerprint so a drop-in dir
//!     change (`/etc/sysctl.d`, `/etc/modules-load.d`, `/etc/nftables.d`)
//!     makes the owning unit reconcile even when its own unit file is
//!     byte-identical — the AOS analogue of `sysinit-reactivation.target`.
//!   - The upstream fstab/swap reconciliation pipeline
//!     (`main.rs:903-1900` family) is out of scope; the only mount handling
//!     is the `-.mount` / `var.mount` denylist (§6.5).
//!   - `socket_map` and `warnings` are carried on [`UnitDiff`] for the
//!     caller (P4) and tests; they are not in the design spec's struct.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::sysroot::djb2_hash;

/// Mount units that must never be restarted on a file change: restarting
/// `-.mount` would `umount /` on the live system, and restarting `var.mount`
/// tears down `/var` while the new generation depends on `/var/etc` being live
/// (it is one of the overlay's lower layers) and every daemon writes state
/// there. A changed denylisted mount reconciles via reload instead.
const NEVER_RESTART_MOUNTS: &[&str] = &["-.mount", "var.mount"];

/// `[Unit]` keys that do not affect runtime behaviour and are stripped before
/// fingerprinting, so a pure documentation/metadata edit does not churn a unit.
/// `X-Reload-Triggers` is consumed by the diff engine (its *content* is folded
/// into the effective fingerprint), not compared as literal text — so it is
/// excluded here too.
///
/// cribbed from switch-to-configuration-ng (`main.rs:503-520`).
const IGNORED_UNIT_KEYS: &[&str] = &[
    "Description",
    "Documentation",
    "OnFailure",
    "OnSuccess",
    "OnFailureJobMode",
    "IgnoreOnIsolate",
    "StopWhenUnneeded",
    "RefuseManualStart",
    "RefuseManualStop",
    "AllowIsolate",
    "CollectMode",
    "SourcePath",
    "X-Reload-Triggers",
];

/// Filename extensions that mark a regular file as a primary unit file.
const UNIT_EXTS: &[&str] = &[
    "service",
    "socket",
    "target",
    "mount",
    "timer",
    "path",
    "slice",
    "automount",
    "swap",
];

// ---------------------------------------------------------------------------
// Parsed unit (INI)
// ---------------------------------------------------------------------------

/// A parsed systemd unit/drop-in: section → key → ordered values.
///
/// Multi-value keys (`ExecStartPre=`, `EnvironmentFile=`, `WantedBy=`, …)
/// preserve declaration order via the `Vec`. An empty assignment (`Key=`)
/// clears the accumulated values — systemd's drop-in reset semantic.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Parsed {
    /// `section name -> key -> values in declaration order`.
    pub sections: BTreeMap<String, BTreeMap<String, Vec<String>>>,
}

impl Parsed {
    /// Parse systemd-INI text.
    ///
    /// cribbed from switch-to-configuration-ng `parse_systemd_ini`
    /// (`main.rs:344-411`). Handles section headers, `#`/`;` comments, line
    /// continuations (a value line ending in `\` joins the next physical
    /// line), multi-value append, and the empty-value-clears reset.
    pub fn parse(text: &str) -> Parsed {
        let mut sections: BTreeMap<String, BTreeMap<String, Vec<String>>> = BTreeMap::new();
        let mut section: Option<String> = None;

        for logical in join_continuations(text) {
            let line = logical.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            if line.starts_with('[') && line.ends_with(']') {
                section = Some(line[1..line.len() - 1].to_string());
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                // A line with no `=` outside any section is not valid systemd
                // syntax; ignore it rather than failing the whole reconcile.
                continue;
            };
            let Some(sec) = section.as_ref() else {
                continue;
            };
            let key = key.trim().to_string();
            let value = value.trim();
            let entry = sections
                .entry(sec.clone())
                .or_default()
                .entry(key)
                .or_default();
            if value.is_empty() {
                // `Key=` resets the accumulated list (drop-in reset semantic).
                entry.clear();
            } else {
                entry.push(value.to_string());
            }
        }

        Parsed { sections }
    }

    /// Structural fingerprint, excluding the `[Install]` section and the
    /// ignored `[Unit]` keys. Canonical encoding: sections sorted, keys sorted
    /// within each section (both via `BTreeMap`), values in declaration order.
    fn fingerprint(&self) -> u64 {
        let mut canonical = String::new();
        for (sec, keys) in &self.sections {
            if sec == "Install" {
                continue;
            }
            canonical.push('[');
            canonical.push_str(sec);
            canonical.push_str("]\n");
            for (key, values) in keys {
                if sec == "Unit" && IGNORED_UNIT_KEYS.contains(&key.as_str()) {
                    continue;
                }
                for v in values {
                    canonical.push_str(key);
                    canonical.push('=');
                    canonical.push_str(v);
                    canonical.push('\n');
                }
            }
        }
        djb2_hash(canonical.as_bytes())
    }
}

/// Join physical lines into logical lines across trailing-`\` continuations.
fn join_continuations(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut acc: Option<String> = None;
    for raw in text.lines() {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if let Some(prefix) = line.strip_suffix('\\') {
            acc.get_or_insert_with(String::new).push_str(prefix);
        } else if let Some(mut started) = acc.take() {
            started.push_str(line);
            out.push(started);
        } else {
            out.push(line.to_string());
        }
    }
    if let Some(started) = acc.take() {
        out.push(started);
    }
    out
}

// ---------------------------------------------------------------------------
// Logical unit model
// ---------------------------------------------------------------------------

/// A single on-disk unit file or drop-in, with its parsed content + hash.
#[derive(Debug, Clone)]
pub struct UnitFile {
    /// Path on disk (for diagnostics).
    pub path: PathBuf,
    /// Parsed INI sections.
    pub parsed: Parsed,
    /// Structural fingerprint of `parsed` (ignored keys / `[Install]` excluded).
    pub fingerprint: u64,
}

impl UnitFile {
    /// Read, parse, and fingerprint one unit file; `None` if unreadable.
    fn load(path: PathBuf) -> Option<UnitFile> {
        // `fs::read` follows symlinks, so a unit shipped as a store-path
        // symlink (the generateUnits norm) resolves to its real content.
        let bytes = std::fs::read(&path).ok()?;
        let text = String::from_utf8_lossy(&bytes);
        let parsed = Parsed::parse(&text);
        let fingerprint = parsed.fingerprint();
        Some(UnitFile {
            path,
            parsed,
            fingerprint,
        })
    }
}

/// A logical unit = its primary file (if any) plus ordered drop-ins, plus the
/// install-symlink state recorded from `*.<target>.{wants,requires,upholds}/`.
#[derive(Debug, Clone, Default)]
pub struct LogicalUnit {
    /// Unit name including extension (e.g. `nginx.service`).
    pub name: String,
    /// The primary `<name>` unit file in `/etc`, if shipped there.
    pub primary: Option<UnitFile>,
    /// Drop-ins from `<name>.d/*.conf`, sorted by filename (override order).
    pub drop_ins: Vec<UnitFile>,
    /// Targets whose `.wants/` reference this unit.
    pub install_wants: BTreeSet<String>,
    /// Targets whose `.requires/` reference this unit.
    pub install_requires: BTreeSet<String>,
    /// Targets whose `.upholds/` reference this unit.
    pub install_upholds: BTreeSet<String>,
    /// Masked: the unit name is a symlink to `/dev/null`.
    pub masked: bool,
}

impl LogicalUnit {
    /// Whether this unit is effectively present (not masked, and backed by
    /// either a primary file or at least one drop-in). A drop-in-only unit is
    /// "present": AOS overrides systemd-shipped units (e.g. `systemd-sysctl`,
    /// `systemd-modules-load`) via `<name>.service.d/overrides.conf` while the
    /// primary lives under `/usr/lib`, invisible to this `/etc`-only walk.
    fn is_present(&self) -> bool {
        !self.masked && (self.primary.is_some() || !self.drop_ins.is_empty())
    }

    /// The merged `[Section] key=values` view: primary first, then each
    /// drop-in concatenated in order. Used for reading the `X-*` knobs and
    /// detecting `ExecReload=`; the fingerprint folds per-file hashes
    /// separately (see [`file_fp`]) and does not use this merge.
    fn merged(&self) -> BTreeMap<String, BTreeMap<String, Vec<String>>> {
        let mut merged: BTreeMap<String, BTreeMap<String, Vec<String>>> = BTreeMap::new();
        let files = self.primary.iter().chain(self.drop_ins.iter());
        for f in files {
            for (sec, keys) in &f.parsed.sections {
                let dst = merged.entry(sec.clone()).or_default();
                for (key, values) in keys {
                    dst.entry(key.clone())
                        .or_default()
                        .extend(values.iter().cloned());
                }
            }
        }
        merged
    }
}

/// The full set of units found under one side's `systemd/system/`.
#[derive(Debug, Default)]
pub struct UnitMap {
    /// Logical units keyed by unit name.
    pub units: BTreeMap<String, LogicalUnit>,
}

// ---------------------------------------------------------------------------
// Diff result
// ---------------------------------------------------------------------------

/// The computed reconciliation plan. Action lists are disjoint; `blanket_targets`
/// is an annotation (a subset of `to_restart`/`to_reload`) naming the units that
/// reconcile only because one of their `X-Reload-Triggers` paths changed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServiceRootBarrier {
    /// Owning package target stopped while the old helper is still loaded.
    pub target: String,
    /// Units controlled by the live target and therefore stopped with it.
    pub live_members: BTreeSet<String>,
    /// Units controlled by the candidate target and started with it.
    pub candidate_members: BTreeSet<String>,
    /// Whether the owning target remains present in the candidate.
    pub candidate_target_present: bool,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct UnitDiff {
    /// Authenticated generated roots helpers and their target membership.
    pub service_root_barriers: BTreeMap<String, ServiceRootBarrier>,
    /// Stops that must complete successfully before the generation can swap.
    pub required_stops: BTreeSet<String>,
    /// Present live, gone in candidate → stop (minus `X-StopOnRemoval=false`).
    pub to_stop: Vec<String>,
    /// Absent live, present in candidate → start (minus `X-OnlyManualStart=true`).
    pub to_start: Vec<String>,
    /// Present both, changed, restart policy says restart.
    pub to_restart: Vec<String>,
    /// Present both, changed, reload policy says reload.
    pub to_reload: Vec<String>,
    /// Unchanged unit whose install symlinks changed → (re)start to pick up
    /// new dependency wiring.
    pub install_only: Vec<String>,
    /// Units that reconcile because a reload-trigger path's content changed
    /// (already present in `to_restart`/`to_reload`; surfaced for logging).
    pub blanket_targets: Vec<String>,
    /// Candidate `service → [sockets]` map for socket-first ordering (§6.7).
    pub socket_map: BTreeMap<String, Vec<String>>,
    /// Non-fatal advisories (e.g. `reloadIfChanged` on a unit with no
    /// `ExecReload=`, which falls back to restart).
    pub warnings: Vec<String>,
}

impl UnitDiff {
    /// Replaces affected service-root member actions with an ordered, required
    /// old-member, old-helper, and owning-target stop barrier.
    pub fn normalize_service_root_lifecycle(&mut self) {
        let affected_helpers = self
            .to_restart
            .iter()
            .chain(&self.to_stop)
            .filter(|unit| self.service_root_barriers.contains_key(*unit))
            .cloned()
            .collect::<BTreeSet<_>>();

        for helper in affected_helpers {
            let barrier = self.service_root_barriers[&helper].clone();
            let members = barrier
                .live_members
                .union(&barrier.candidate_members)
                .cloned()
                .chain([helper.clone(), barrier.target.clone()])
                .collect::<BTreeSet<_>>();
            self.to_stop.retain(|unit| !members.contains(unit));
            self.to_restart.retain(|unit| !members.contains(unit));
            self.to_reload.retain(|unit| !members.contains(unit));
            self.to_start.retain(|unit| !members.contains(unit));
            self.install_only.retain(|unit| !members.contains(unit));
            self.blanket_targets.retain(|unit| !members.contains(unit));

            // Stop every authenticated old member explicitly so the later
            // target stop cannot race PartOf-propagated helper cleanup.
            for member in barrier
                .live_members
                .iter()
                .filter(|member| *member != &helper && *member != &barrier.target)
            {
                self.to_stop.push(member.clone());
                self.required_stops.insert(member.clone());
            }

            // The helper is now independent of propagation, so this job result
            // is the authoritative old-overlay cleanup outcome.
            self.to_stop.push(helper.clone());
            self.required_stops.insert(helper);

            self.to_stop.push(barrier.target.clone());
            self.required_stops.insert(barrier.target.clone());

            if barrier.candidate_target_present && !self.to_start.contains(&barrier.target) {
                self.to_start.push(barrier.target);
            }
        }
    }
}

/// Returns the package target owning a generated service-root preparation unit.
///
/// The expose renderer reserves this exact name. Keeping the derivation here
/// lets both generation activation and attached-unit reconciliation establish
/// the same pre-reload stop barrier while the old strict cleanup command is
/// still loaded.
pub(crate) fn service_root_target(unit: &str) -> Option<String> {
    let package = unit
        .strip_prefix("aos-pkg-")?
        .strip_suffix("-service-roots.service")?;
    if package.is_empty() {
        return None;
    }
    Some(format!("aos-pkg-{package}.target"))
}

// ---------------------------------------------------------------------------
// Unit-type policy
// ---------------------------------------------------------------------------

/// Coarse unit-type classification driving the per-type policy
/// (cribbed from switch-to-configuration-ng `main.rs:691-755`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnitType {
    /// Full restart/reload/stop/start lifecycle.
    Active,
    /// `.target` — never restarted directly; stopped for an explicit
    /// reconfiguration barrier or when its final install edge is removed.
    Target,
    /// `.slice` / `.path` — config picked up by daemon-reload; not restarted.
    ReloadOnly,
    /// `.scope` (and unknown extensions) — third-party-managed; never touched.
    Excluded,
}

/// Classify a unit by its filename extension.
fn unit_type(name: &str) -> UnitType {
    match name.rsplit('.').next().unwrap_or("") {
        "service" | "socket" | "timer" | "mount" | "automount" | "swap" => UnitType::Active,
        "target" => UnitType::Target,
        "slice" | "path" => UnitType::ReloadOnly,
        _ => UnitType::Excluded,
    }
}

/// Whether the unit is one of the never-restart mounts ([`NEVER_RESTART_MOUNTS`]).
fn is_denylisted_mount(name: &str) -> bool {
    NEVER_RESTART_MOUNTS.contains(&name)
}

/// The `X-*` contract knobs, resolved from a merged `[Unit]` section with the
/// gated-emission defaults from the module renderer: a knob is absent at its
/// default and only emitted when set to its non-default value.
#[derive(Debug, Clone, Copy)]
struct Knobs {
    restart_if_changed: bool,
    reload_if_changed: bool,
    #[allow(dead_code)] // parsed for completeness; restart_unit is in-place.
    stop_if_changed: bool,
    stop_on_removal: bool,
    stop_on_reconfiguration: bool,
    only_manual_start: bool,
    not_socket_activated: bool,
}

impl Knobs {
    /// Read the knobs from a merged `[Unit]` section, applying defaults for
    /// absent keys; the last assignment of a repeated key wins.
    fn from_merged(merged: &BTreeMap<String, BTreeMap<String, Vec<String>>>) -> Knobs {
        let unit = merged.get("Unit");
        let read = |key: &str, default: bool| -> bool {
            unit.and_then(|m| m.get(key))
                .and_then(|v| v.last())
                .map(|s| parse_bool(s))
                .unwrap_or(default)
        };
        Knobs {
            restart_if_changed: read("X-RestartIfChanged", true),
            reload_if_changed: read("X-ReloadIfChanged", false),
            stop_if_changed: read("X-StopIfChanged", true),
            stop_on_removal: read("X-StopOnRemoval", true),
            stop_on_reconfiguration: read("X-StopOnReconfiguration", false),
            only_manual_start: read("X-OnlyManualStart", false),
            not_socket_activated: read("X-NotSocketActivated", false),
        }
    }
}

/// systemd-style boolean parse (`1`/`yes`/`true`/`on` are true).
fn parse_bool(s: &str) -> bool {
    matches!(
        s.trim().to_ascii_lowercase().as_str(),
        "1" | "yes" | "true" | "on"
    )
}

/// Whether the merged unit declares a non-empty `[Service] ExecReload=`.
fn has_exec_reload(merged: &BTreeMap<String, BTreeMap<String, Vec<String>>>) -> bool {
    merged
        .get("Service")
        .and_then(|s| s.get("ExecReload"))
        .map(|v| v.iter().any(|x| !x.is_empty()))
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Walk a side's systemd/system tree
// ---------------------------------------------------------------------------

/// Build the [`UnitMap`] for one side by scanning a `systemd/system/`
/// directory: primary unit files, `<name>.d/*.conf` drop-ins, mask symlinks
/// to `/dev/null`, and `<target>.{wants,requires,upholds}/` install links.
/// An unreadable directory yields an empty map.
fn walk(units_dir: &Path) -> UnitMap {
    let mut units: BTreeMap<String, LogicalUnit> = BTreeMap::new();
    let Ok(entries) = std::fs::read_dir(units_dir) else {
        return UnitMap { units };
    };

    let unit = |units: &mut BTreeMap<String, LogicalUnit>, name: &str| {
        units
            .entry(name.to_string())
            .or_insert_with(|| LogicalUnit {
                name: name.to_string(),
                ..Default::default()
            });
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();

        // Masking: a unit name symlinked to /dev/null.
        if let Ok(lmeta) = std::fs::symlink_metadata(&path)
            && lmeta.file_type().is_symlink()
            && let Ok(target) = std::fs::read_link(&path)
            && target == Path::new("/dev/null")
        {
            unit(&mut units, &name);
            units.get_mut(&name).unwrap().masked = true;
            continue;
        }

        // Follow symlinks to classify dir-vs-file.
        let Ok(meta) = std::fs::metadata(&path) else {
            continue; // dangling symlink or vanished entry
        };

        if meta.is_dir() {
            if let Some(base) = name.strip_suffix(".d") {
                // Drop-in directory: collect *.conf, sorted by filename.
                let mut confs: Vec<PathBuf> = std::fs::read_dir(&path)
                    .map(|rd| {
                        rd.flatten()
                            .map(|e| e.path())
                            .filter(|p| p.extension().map(|x| x == "conf").unwrap_or(false))
                            .collect()
                    })
                    .unwrap_or_default();
                confs.sort();
                unit(&mut units, base);
                let lu = units.get_mut(base).unwrap();
                for c in confs {
                    if let Some(uf) = UnitFile::load(c) {
                        lu.drop_ins.push(uf);
                    }
                }
            } else if let Some(kind_base) = install_dir_kind(&name) {
                // <target>.wants / .requires / .upholds: each entry's name is
                // the dependent unit; record this base target into its set.
                let (base_target, kind) = kind_base;
                if let Ok(rd) = std::fs::read_dir(&path) {
                    for dep in rd.flatten() {
                        let dep_name = dep.file_name().to_string_lossy().into_owned();
                        unit(&mut units, &dep_name);
                        let lu = units.get_mut(&dep_name).unwrap();
                        match kind {
                            InstallKind::Wants => lu.install_wants.insert(base_target.clone()),
                            InstallKind::Requires => {
                                lu.install_requires.insert(base_target.clone())
                            }
                            InstallKind::Upholds => lu.install_upholds.insert(base_target.clone()),
                        };
                    }
                }
            }
            // Other directories are ignored.
        } else if meta.is_file()
            && has_unit_ext(&name)
            && let Some(uf) = UnitFile::load(path)
        {
            unit(&mut units, &name);
            units.get_mut(&name).unwrap().primary = Some(uf);
        }
    }

    UnitMap { units }
}

/// Whether the filename carries one of the primary unit extensions.
fn has_unit_ext(name: &str) -> bool {
    name.rsplit('.')
        .next()
        .map(|ext| UNIT_EXTS.contains(&ext))
        .unwrap_or(false)
}

/// The three install-symlink directory flavors.
#[derive(Clone, Copy)]
enum InstallKind {
    Wants,
    Requires,
    Upholds,
}

/// Classify an install directory (`foo.target.wants` → ("foo.target", Wants)).
fn install_dir_kind(name: &str) -> Option<(String, InstallKind)> {
    for (suffix, kind) in [
        (".wants", InstallKind::Wants),
        (".requires", InstallKind::Requires),
        (".upholds", InstallKind::Upholds),
    ] {
        if let Some(base) = name.strip_suffix(suffix) {
            return Some((base.to_string(), kind));
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Fingerprinting (unit files + referenced runtime content)
// ---------------------------------------------------------------------------

/// The unit's structural fingerprint over its own files only: the primary
/// rotated and XOR-folded with an order-sensitive fold of the drop-ins (so
/// override order, which determines precedence, matters).
fn file_fp(u: &LogicalUnit) -> u64 {
    let primary_fp = u.primary.as_ref().map(|f| f.fingerprint).unwrap_or(0);
    let drop_in_fp = u
        .drop_ins
        .iter()
        .map(|d| d.fingerprint)
        .fold(0u64, |acc, fp| acc.wrapping_mul(31).wrapping_add(fp));
    primary_fp.rotate_left(13) ^ drop_in_fp
}

/// Fold the *content* of each `X-Reload-Triggers` path (resolved against the
/// side's `/etc` root) into a hash. `None` when the unit declares no triggers,
/// so trigger-less units' effective fingerprint equals their file fingerprint.
fn trigger_fp(u: &LogicalUnit, etc_root: &Path) -> Option<u64> {
    let merged = u.merged();
    let raw = merged.get("Unit")?.get("X-Reload-Triggers")?;
    let mut paths: Vec<&str> = Vec::new();
    for v in raw {
        paths.extend(v.split_whitespace());
    }
    if paths.is_empty() {
        return None;
    }
    let mut acc = 5381u64;
    for p in paths {
        let resolved = rebase_trigger(Path::new(p), etc_root);
        acc = acc.wrapping_mul(31).wrapping_add(content_hash(&resolved));
    }
    Some(acc)
}

/// Folds generation-local job scripts owned by this unit into a content hash.
///
/// Runtime-evaluated units refer to stable `/etc/aos-job-scripts/<key>` paths,
/// so their unit-file text does not change when a script body changes. Keys are
/// namespaced as `<unit>:<slot>`, which lets reconciliation bind the referenced
/// script bytes to their owning unit without consulting an untrusted manifest.
fn job_scripts_fp(u: &LogicalUnit, etc_root: &Path) -> Option<u64> {
    let scripts_dir = etc_root.join("aos-job-scripts");
    let prefix = format!("{}:", u.name);
    let mut scripts: Vec<_> = std::fs::read_dir(scripts_dir)
        .ok()?
        .flatten()
        .filter(|entry| entry.file_name().to_string_lossy().starts_with(&prefix))
        .collect();
    scripts.sort_by_key(|entry| entry.file_name());
    if scripts.is_empty() {
        return None;
    }

    let mut acc = 5381u64;
    for script in scripts {
        let name = script.file_name();
        acc = acc
            .wrapping_mul(31)
            .wrapping_add(djb2_hash(name.to_string_lossy().as_bytes()))
            .rotate_left(5)
            ^ content_hash(&script.path());
    }
    Some(acc)
}

/// Effective fingerprint = file fingerprint, with reload-trigger and
/// generation-local job-script content folded in when present.
fn effective_fp(u: &LogicalUnit, etc_root: &Path) -> u64 {
    let mut fingerprint = file_fp(u);
    if let Some(triggers) = trigger_fp(u, etc_root) {
        fingerprint = fingerprint.rotate_left(7) ^ triggers;
    }
    if let Some(job_scripts) = job_scripts_fp(u, etc_root) {
        fingerprint = fingerprint.rotate_left(11) ^ job_scripts;
    }
    fingerprint
}

/// Resolve an absolute trigger path (canonically under `/etc`) onto a side's
/// `/etc` root. Live runs pass `/etc`; the candidate side passes the private
/// `$tmpEtc` overlay root, so `/etc/sysctl.d` → `$tmpEtc/sysctl.d`.
fn rebase_trigger(trigger: &Path, etc_root: &Path) -> PathBuf {
    match trigger.strip_prefix("/etc") {
        Ok(rel) => etc_root.join(rel),
        Err(_) => trigger.to_path_buf(),
    }
}

/// Deterministic content hash of a file or directory tree. Distinct non-zero
/// sentinels keep "absent" different from "empty dir" different from a real
/// file, so a trigger path appearing/disappearing changes the hash.
fn content_hash(path: &Path) -> u64 {
    let Ok(meta) = std::fs::metadata(path) else {
        return 1; // absent / unreadable
    };
    if meta.is_dir() {
        let mut entries: Vec<_> = match std::fs::read_dir(path) {
            Ok(rd) => rd.flatten().collect(),
            Err(_) => return 2,
        };
        entries.sort_by_key(|e| e.file_name());
        let mut acc = 5381u64;
        for e in entries {
            let name_h = djb2_hash(e.file_name().to_string_lossy().as_bytes());
            let child = content_hash(&e.path());
            acc = acc.wrapping_mul(31).wrapping_add(name_h).rotate_left(5) ^ child;
        }
        acc
    } else if meta.is_file() {
        match std::fs::read(path) {
            Ok(bytes) => djb2_hash(&bytes),
            Err(_) => 3,
        }
    } else {
        4 // device/socket/fifo etc.
    }
}

// ---------------------------------------------------------------------------
// Diff computation
// ---------------------------------------------------------------------------

/// Compute the reconciliation plan between the live `/etc` and a candidate
/// `/etc` overlay.
///
/// Both arguments are `/etc` *roots* (the unit tree is read from
/// `<root>/systemd/system/`); the root is also where each unit's absolute
/// `X-Reload-Triggers` paths are rebased to. In production the caller passes
/// `Path::new("/etc")` and the candidate `$tmpEtc`.
///
/// cribbed from switch-to-configuration-ng `compare_units` /
/// `handle_modified_unit` (`main.rs:488-755`).
pub fn compute_diff(live_etc_root: &Path, candidate_etc_root: &Path) -> UnitDiff {
    let live = walk(&live_etc_root.join("systemd/system"));
    let candidate = walk(&candidate_etc_root.join("systemd/system"));

    let mut diff = UnitDiff::default();

    diff.service_root_barriers = build_service_root_barriers(&live, &candidate);

    let names: BTreeSet<&String> = live.units.keys().chain(candidate.units.keys()).collect();

    for name in names {
        let l = live.units.get(name);
        let c = candidate.units.get(name);
        let l_present = l.map(|u| u.is_present()).unwrap_or(false);
        let c_present = c.map(|u| u.is_present()).unwrap_or(false);

        match (l_present, c_present) {
            (true, false) => classify_removed(name, l.unwrap(), &mut diff),
            (false, true) => classify_added(name, c.unwrap(), &mut diff),
            (true, true) => classify_both(
                name,
                l.unwrap(),
                c.unwrap(),
                live_etc_root,
                candidate_etc_root,
                &mut diff,
            ),
            (false, false) => {}
        }
    }

    diff.socket_map = build_socket_map(&candidate);
    order_sockets_first(&mut diff.to_restart);
    order_sockets_first(&mut diff.to_start);

    diff
}

fn build_service_root_barriers(
    live: &UnitMap,
    candidate: &UnitMap,
) -> BTreeMap<String, ServiceRootBarrier> {
    let helper_names = live
        .units
        .keys()
        .chain(candidate.units.keys())
        .filter(|name| service_root_target(name).is_some())
        .cloned()
        .collect::<BTreeSet<_>>();

    helper_names
        .into_iter()
        .filter_map(|helper| {
            let target = service_root_target(&helper)?;
            let live_helper = live.units.get(&helper).filter(|unit| unit.is_present());
            let candidate_helper = candidate
                .units
                .get(&helper)
                .filter(|unit| unit.is_present());
            let helper_is_bound = live_helper
                .into_iter()
                .chain(candidate_helper)
                .all(|unit| unit_section_words(unit, "PartOf") == BTreeSet::from([target.clone()]));
            if !helper_is_bound || (live_helper.is_none() && candidate_helper.is_none()) {
                return None;
            }

            Some((
                helper,
                ServiceRootBarrier {
                    live_members: target_members(live, &target),
                    candidate_members: target_members(candidate, &target),
                    candidate_target_present: candidate
                        .units
                        .get(&target)
                        .is_some_and(LogicalUnit::is_present),
                    target,
                },
            ))
        })
        .collect()
}

fn target_members(units: &UnitMap, target: &str) -> BTreeSet<String> {
    let wanted = units
        .units
        .get(target)
        .filter(|unit| unit.is_present())
        .map(|unit| unit_section_words(unit, "Wants"))
        .unwrap_or_default();

    units
        .units
        .iter()
        .filter(|(name, unit)| {
            unit.is_present()
                && (wanted.contains(*name) || unit_section_words(unit, "PartOf").contains(target))
        })
        .map(|(name, _)| name.clone())
        .collect()
}

fn unit_section_words(unit: &LogicalUnit, key: &str) -> BTreeSet<String> {
    unit.merged()
        .get("Unit")
        .and_then(|section| section.get(key))
        .into_iter()
        .flatten()
        .flat_map(|value| value.split_ascii_whitespace())
        .map(str::to_string)
        .collect()
}

/// Route a unit present live but gone in the candidate: stop it, unless it
/// is drop-in-only, non-Active, a denylisted mount, or opted out via
/// `X-StopOnRemoval=false`.
fn classify_removed(name: &str, live: &LogicalUnit, diff: &mut UnitDiff) {
    // Only a unit with its own primary in /etc is "stopped" on removal —
    // a removed drop-in modifies a still-shipped systemd unit, handled by
    // daemon-reload.
    if live.primary.is_none() {
        return;
    }
    match unit_type(name) {
        UnitType::Target if install_link_count(live) > 0 => {
            diff.to_stop.push(name.to_string());
            return;
        }
        UnitType::Active => {}
        _ => return,
    }
    if is_denylisted_mount(name) {
        return;
    }
    let knobs = Knobs::from_merged(&live.merged());
    if !knobs.stop_on_removal {
        return;
    }
    diff.to_stop.push(name.to_string());
}

/// Route a unit new in the candidate: start it, unless it is drop-in-only,
/// non-Active, or marked `X-OnlyManualStart=true`.
fn classify_added(name: &str, candidate: &LogicalUnit, diff: &mut UnitDiff) {
    // Drop-in-only additions modify systemd-shipped units → daemon-reload.
    if candidate.primary.is_none() {
        return;
    }
    if unit_type(name) == UnitType::Target {
        if install_link_count(candidate) > 0 {
            diff.install_only.push(name.to_string());
        }
        return;
    }
    if unit_type(name) != UnitType::Active {
        return; // uninstalled targets and slices/paths need only daemon-reload.
    }
    let knobs = Knobs::from_merged(&candidate.merged());
    if knobs.only_manual_start {
        return;
    }
    diff.to_start.push(name.to_string());
}

/// Route a unit present on both sides: compare effective fingerprints and
/// dispatch via [`changed_action`]; a change driven purely by reload-trigger
/// content (identical files) is also recorded in `blanket_targets`.
/// Unchanged units whose install symlinks differ go to `install_only`.
#[allow(clippy::too_many_arguments)]
fn classify_both(
    name: &str,
    live: &LogicalUnit,
    candidate: &LogicalUnit,
    live_root: &Path,
    candidate_root: &Path,
    diff: &mut UnitDiff,
) {
    let l_file = file_fp(live);
    let c_file = file_fp(candidate);
    let l_eff = effective_fp(live, live_root);
    let c_eff = effective_fp(candidate, candidate_root);
    let install_changed = install_changed(live, candidate);

    if l_eff != c_eff {
        // Changed. Route via per-type policy on the candidate's knobs.
        let trigger_driven = l_file == c_file
            && trigger_fp(live, live_root) != trigger_fp(candidate, candidate_root);
        match changed_action(name, candidate, diff) {
            Action::Restart => {
                diff.to_restart.push(name.to_string());
                if trigger_driven {
                    diff.blanket_targets.push(name.to_string());
                }
            }
            Action::Reload => {
                diff.to_reload.push(name.to_string());
                if trigger_driven {
                    diff.blanket_targets.push(name.to_string());
                }
            }
            Action::Stop => diff.to_stop.push(name.to_string()),
            Action::None => {}
        }
    } else {
        // Unchanged active unit: pick up new install wiring.
        if install_changed
            && unit_type(name) == UnitType::Active
            && !Knobs::from_merged(&candidate.merged()).only_manual_start
        {
            diff.install_only.push(name.to_string());
        }
    }

    // Target enablement is policy, independent of whether the target body also
    // changed (for example when deselection restores an image-bundled unit).
    if install_changed && unit_type(name) == UnitType::Target {
        if install_link_count(candidate) > 0 {
            if !diff.install_only.iter().any(|unit| unit == name) {
                diff.install_only.push(name.to_string());
            }
        } else if install_link_count(live) > 0 && !diff.to_stop.iter().any(|unit| unit == name) {
            diff.to_stop.push(name.to_string());
        }
    }
}

fn install_link_count(unit: &LogicalUnit) -> usize {
    unit.install_wants.len() + unit.install_requires.len() + unit.install_upholds.len()
}

/// The classification of a *changed* (present-on-both) unit. Additions and
/// removals are handled directly in [`classify_added`] / [`classify_removed`],
/// so there is no `Start` variant here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    Stop,
    Restart,
    Reload,
    None,
}

/// The action for a changed unit, by type policy + `X-*` knobs (read from the
/// candidate's merged `[Unit]`). Pushes a `warnings` entry when
/// `reloadIfChanged` is requested but the unit has no `ExecReload=`.
fn changed_action(name: &str, candidate: &LogicalUnit, diff: &mut UnitDiff) -> Action {
    match unit_type(name) {
        UnitType::Excluded | UnitType::ReloadOnly => Action::None,
        UnitType::Target => {
            let knobs = Knobs::from_merged(&candidate.merged());
            if knobs.stop_on_reconfiguration {
                Action::Stop
            } else {
                Action::None
            }
        }
        UnitType::Active => {
            if is_denylisted_mount(name) {
                // Root/var: never restart on change; reload is a safe no-op.
                return Action::Reload;
            }
            let merged = candidate.merged();
            let knobs = Knobs::from_merged(&merged);
            if !knobs.restart_if_changed {
                return Action::None;
            }
            if knobs.reload_if_changed {
                if has_exec_reload(&merged) {
                    return Action::Reload;
                }
                diff.warnings.push(format!(
                    "{name}: reloadIfChanged set but no ExecReload=; falling back to restart"
                ));
            }
            Action::Restart
        }
    }
}

/// Whether any of the wants/requires/upholds install sets differ.
fn install_changed(live: &LogicalUnit, candidate: &LogicalUnit) -> bool {
    live.install_wants != candidate.install_wants
        || live.install_requires != candidate.install_requires
        || live.install_upholds != candidate.install_upholds
}

// ---------------------------------------------------------------------------
// Socket activation (§6.7)
// ---------------------------------------------------------------------------

/// Build the candidate `service → [sockets]` map: for each present `.socket`,
/// resolve the service via `[Socket] Service=` or the `<base>.service`
/// heuristic, unless that service opts out via `X-NotSocketActivated=true`.
///
/// cribbed from switch-to-configuration-ng (`main.rs:803-816`).
fn build_socket_map(candidate: &UnitMap) -> BTreeMap<String, Vec<String>> {
    let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (name, u) in &candidate.units {
        if !u.is_present() || unit_type(name) != UnitType::Active || !name.ends_with(".socket") {
            continue;
        }
        let merged = u.merged();
        let service = merged
            .get("Socket")
            .and_then(|s| s.get("Service"))
            .and_then(|v| v.last())
            .cloned()
            .unwrap_or_else(|| format!("{}.service", name.trim_end_matches(".socket")));

        if let Some(svc) = candidate.units.get(&service)
            && Knobs::from_merged(&svc.merged()).not_socket_activated
        {
            continue;
        }
        map.entry(service).or_default().push(name.clone());
    }
    for sockets in map.values_mut() {
        sockets.sort();
    }
    map
}

/// Reorder a unit list so `.socket` units precede the rest (stable), keeping
/// the listen fd open across a socket-activated service's restart.
fn order_sockets_first(list: &mut [String]) {
    list.sort_by_key(|n| if n.ends_with(".socket") { 0 } else { 1 });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::path::Path;
    use tempfile::TempDir;

    // --- INI parser -----------------------------------------------------

    #[test]
    fn parse_appends_multi_value_keys() {
        let p =
            Parsed::parse("[Service]\nExecStartPre=/bin/a\nExecStartPre=/bin/b\nType=oneshot\n");
        let svc = &p.sections["Service"];
        assert_eq!(svc["ExecStartPre"], vec!["/bin/a", "/bin/b"]);
        assert_eq!(svc["Type"], vec!["oneshot"]);
    }

    #[test]
    fn parse_empty_value_clears_accumulated() {
        // The drop-in reset semantic: `Key=` wipes the prior values.
        let p = Parsed::parse("[Service]\nExecStart=/bin/old\nExecStart=\nExecStart=/bin/new\n");
        assert_eq!(p.sections["Service"]["ExecStart"], vec!["/bin/new"]);

        let cleared = Parsed::parse("[Service]\nEnvironment=A=1\nEnvironment=\n");
        assert!(cleared.sections["Service"]["Environment"].is_empty());
    }

    #[test]
    fn parse_handles_comments_and_continuations() {
        let p =
            Parsed::parse("# comment\n; also comment\n[Unit]\nDescription=line one \\\nand two\n");
        assert_eq!(p.sections["Unit"]["Description"], vec!["line one and two"]);
    }

    #[test]
    fn fingerprint_ignores_install_and_ignored_unit_keys() {
        let a = Parsed::parse(
            "[Unit]\nDescription=A\nRequires=x.service\n[Install]\nWantedBy=multi-user.target\n",
        );
        let b = Parsed::parse(
            "[Unit]\nDescription=COMPLETELY DIFFERENT\nRequires=x.service\n[Install]\nWantedBy=other.target\n",
        );
        // Only Description (ignored) and [Install] (excluded) differ.
        assert_eq!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn fingerprint_reflects_meaningful_change() {
        let a = Parsed::parse("[Service]\nExecStart=/bin/a\n");
        let b = Parsed::parse("[Service]\nExecStart=/bin/b\n");
        assert_ne!(a.fingerprint(), b.fingerprint());
    }

    // --- test tree helpers ---------------------------------------------

    fn units_dir(root: &Path) -> PathBuf {
        let d = root.join("systemd/system");
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn write(dir: &Path, rel: &str, content: &str) {
        let p = dir.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(p, content).unwrap();
    }

    // --- diff: add / remove / change -----------------------------------

    #[test]
    fn added_service_is_started() {
        let live = TempDir::new().unwrap();
        let cand = TempDir::new().unwrap();
        units_dir(live.path());
        let cu = units_dir(cand.path());
        write(&cu, "new.service", "[Service]\nExecStart=/bin/true\n");

        let diff = compute_diff(live.path(), cand.path());
        assert_eq!(diff.to_start, vec!["new.service"]);
        assert!(diff.to_stop.is_empty() && diff.to_restart.is_empty());
    }

    #[test]
    fn generated_service_root_name_maps_to_owning_target() {
        assert_eq!(
            service_root_target("aos-pkg-libc++=debug-service-roots.service"),
            Some("aos-pkg-libc++=debug.target".to_string())
        );
        assert_eq!(service_root_target("web.service"), None);
        assert_eq!(service_root_target("aos-pkg--service-roots.service"), None);
    }

    #[test]
    fn diff_carries_bound_root_target_members_across_socket_only_transition() {
        let live = TempDir::new().unwrap();
        let candidate = TempDir::new().unwrap();
        let live_units = units_dir(live.path());
        let candidate_units = units_dir(candidate.path());
        let helper = "aos-pkg-web-service-roots.service";

        write(
            &live_units,
            helper,
            "[Unit]\nPartOf=aos-pkg-web.target\n[Service]\nType=oneshot\n",
        );
        write(
            &live_units,
            "aos-pkg-web.target",
            "[Unit]\nWants=web.service wanted-only.service\n",
        );
        write(
            &live_units,
            "web.service",
            "[Unit]\nPartOf=aos-pkg-web.target\n[Service]\nExecStart=/bin/old\n",
        );
        write(
            &live_units,
            "socket-activated.service",
            "[Unit]\nPartOf=aos-pkg-web.target\n[Service]\nExecStart=/bin/socket-activated\n",
        );
        write(
            &live_units,
            "wanted-only.service",
            "[Service]\nExecStart=/bin/wanted-only\n",
        );
        write(
            &candidate_units,
            "aos-pkg-web.target",
            "[Unit]\nWants=web.socket\n",
        );
        write(
            &candidate_units,
            "web.socket",
            "[Unit]\nPartOf=aos-pkg-web.target\n[Socket]\nListenStream=8080\n",
        );

        let mut diff = compute_diff(live.path(), candidate.path());
        let barrier = &diff.service_root_barriers[helper];

        assert_eq!(barrier.target, "aos-pkg-web.target");
        assert!(barrier.live_members.contains("web.service"));
        assert!(barrier.live_members.contains("socket-activated.service"));
        assert!(barrier.live_members.contains("wanted-only.service"));
        assert!(barrier.candidate_members.contains("web.socket"));
        assert!(barrier.candidate_target_present);
        assert!(diff.to_stop.contains(&helper.to_string()));

        diff.normalize_service_root_lifecycle();
        assert_eq!(
            diff.to_stop,
            vec![
                "socket-activated.service",
                "wanted-only.service",
                "web.service",
                "aos-pkg-web-service-roots.service",
                "aos-pkg-web.target",
            ]
        );
        assert_eq!(diff.to_start, vec!["aos-pkg-web.target"]);
        assert!(diff.to_restart.is_empty());
    }

    #[test]
    fn diff_does_not_authorize_foreign_root_target_binding() {
        let live = TempDir::new().unwrap();
        let candidate = TempDir::new().unwrap();
        write(
            &units_dir(live.path()),
            "aos-pkg-victim-service-roots.service",
            "[Unit]\nPartOf=aos-pkg-attacker.target\n[Service]\nType=oneshot\n",
        );

        let diff = compute_diff(live.path(), candidate.path());

        assert!(diff.service_root_barriers.is_empty());
    }

    #[test]
    fn added_enabled_target_is_started() {
        let live = TempDir::new().unwrap();
        let cand = TempDir::new().unwrap();
        units_dir(live.path());
        let cu = units_dir(cand.path());
        write(
            &cu,
            "aos-pkg-web.target",
            "[Unit]\nDescription=Package target\n",
        );
        std::fs::create_dir_all(cu.join("multi-user.target.wants")).unwrap();
        std::os::unix::fs::symlink(
            "../aos-pkg-web.target",
            cu.join("multi-user.target.wants/aos-pkg-web.target"),
        )
        .unwrap();

        let diff = compute_diff(live.path(), cand.path());
        assert_eq!(diff.install_only, vec!["aos-pkg-web.target"]);
        assert!(diff.to_stop.is_empty() && diff.to_restart.is_empty());
    }

    #[test]
    fn removed_service_is_stopped_unless_opt_out() {
        let live = TempDir::new().unwrap();
        let cand = TempDir::new().unwrap();
        let lu = units_dir(live.path());
        units_dir(cand.path());
        write(&lu, "gone.service", "[Service]\nExecStart=/bin/true\n");

        let diff = compute_diff(live.path(), cand.path());
        assert_eq!(diff.to_stop, vec!["gone.service"]);

        // With X-StopOnRemoval=false it is left running.
        let lu2 = units_dir(live.path()); // same dir; overwrite
        write(
            &lu2,
            "gone.service",
            "[Unit]\nX-StopOnRemoval=false\n[Service]\nExecStart=/bin/true\n",
        );
        let diff = compute_diff(live.path(), cand.path());
        assert!(diff.to_stop.is_empty());
    }

    #[test]
    fn changed_service_is_restarted() {
        let live = TempDir::new().unwrap();
        let cand = TempDir::new().unwrap();
        let lu = units_dir(live.path());
        let cu = units_dir(cand.path());
        write(&lu, "svc.service", "[Service]\nExecStart=/bin/old\n");
        write(&cu, "svc.service", "[Service]\nExecStart=/bin/new\n");

        let diff = compute_diff(live.path(), cand.path());
        assert_eq!(diff.to_restart, vec!["svc.service"]);
        assert!(diff.to_reload.is_empty());
    }

    #[test]
    fn changed_generation_local_job_script_restarts_its_unit() {
        let live = TempDir::new().unwrap();
        let cand = TempDir::new().unwrap();
        let lu = units_dir(live.path());
        let cu = units_dir(cand.path());
        let unit = "[Service]\nExecStart=/etc/aos-job-scripts/svc.service:ExecStart.0\n";
        write(&lu, "svc.service", unit);
        write(&cu, "svc.service", unit);
        write(
            live.path(),
            "aos-job-scripts/svc.service:ExecStart.0",
            "printf old\n",
        );
        write(
            cand.path(),
            "aos-job-scripts/svc.service:ExecStart.0",
            "printf new\n",
        );

        let diff = compute_diff(live.path(), cand.path());
        assert_eq!(diff.to_restart, vec!["svc.service"]);
        assert!(diff.blanket_targets.is_empty());
    }

    #[test]
    fn another_units_job_script_does_not_restart_an_unchanged_unit() {
        let live = TempDir::new().unwrap();
        let cand = TempDir::new().unwrap();
        let lu = units_dir(live.path());
        let cu = units_dir(cand.path());
        let unit = "[Service]\nExecStart=/bin/true\n";
        write(&lu, "svc.service", unit);
        write(&cu, "svc.service", unit);
        write(
            live.path(),
            "aos-job-scripts/other.service:ExecStart.0",
            "printf old\n",
        );
        write(
            cand.path(),
            "aos-job-scripts/other.service:ExecStart.0",
            "printf new\n",
        );

        let diff = compute_diff(live.path(), cand.path());
        assert!(diff.to_restart.is_empty());
    }

    #[test]
    fn restart_if_changed_false_is_noop() {
        let live = TempDir::new().unwrap();
        let cand = TempDir::new().unwrap();
        let lu = units_dir(live.path());
        let cu = units_dir(cand.path());
        write(
            &lu,
            "svc.service",
            "[Unit]\nX-RestartIfChanged=false\n[Service]\nExecStart=/bin/old\n",
        );
        write(
            &cu,
            "svc.service",
            "[Unit]\nX-RestartIfChanged=false\n[Service]\nExecStart=/bin/new\n",
        );
        let diff = compute_diff(live.path(), cand.path());
        assert!(diff.to_restart.is_empty() && diff.to_reload.is_empty());
    }

    #[test]
    fn reload_if_changed_with_exec_reload_reloads() {
        let live = TempDir::new().unwrap();
        let cand = TempDir::new().unwrap();
        let lu = units_dir(live.path());
        let cu = units_dir(cand.path());
        let body = |start: &str| {
            format!(
                "[Unit]\nX-ReloadIfChanged=true\n[Service]\nExecStart={start}\nExecReload=/bin/reload\n"
            )
        };
        write(&lu, "svc.service", &body("/bin/old"));
        write(&cu, "svc.service", &body("/bin/new"));
        let diff = compute_diff(live.path(), cand.path());
        assert_eq!(diff.to_reload, vec!["svc.service"]);
        assert!(diff.to_restart.is_empty());
    }

    #[test]
    fn reload_if_changed_without_exec_reload_warns_and_restarts() {
        let live = TempDir::new().unwrap();
        let cand = TempDir::new().unwrap();
        let lu = units_dir(live.path());
        let cu = units_dir(cand.path());
        write(
            &lu,
            "svc.service",
            "[Unit]\nX-ReloadIfChanged=true\n[Service]\nExecStart=/bin/old\n",
        );
        write(
            &cu,
            "svc.service",
            "[Unit]\nX-ReloadIfChanged=true\n[Service]\nExecStart=/bin/new\n",
        );
        let diff = compute_diff(live.path(), cand.path());
        assert_eq!(diff.to_restart, vec!["svc.service"]);
        assert_eq!(diff.warnings.len(), 1);
        assert!(diff.warnings[0].contains("svc.service"));
    }

    // --- mount denylist (§6.5) -----------------------------------------

    #[test]
    fn changed_var_mount_reloads_never_restarts() {
        let live = TempDir::new().unwrap();
        let cand = TempDir::new().unwrap();
        let lu = units_dir(live.path());
        let cu = units_dir(cand.path());
        write(
            &lu,
            "var.mount",
            "[Mount]\nWhat=/dev/sda2\nWhere=/var\nOptions=defaults\n",
        );
        write(
            &cu,
            "var.mount",
            "[Mount]\nWhat=/dev/sda2\nWhere=/var\nOptions=noatime\n",
        );
        let diff = compute_diff(live.path(), cand.path());
        assert_eq!(diff.to_reload, vec!["var.mount"]);
        assert!(diff.to_restart.is_empty());
    }

    // --- target policy --------------------------------------------------

    #[test]
    fn changed_target_default_noop_but_stop_on_reconfiguration() {
        let live = TempDir::new().unwrap();
        let cand = TempDir::new().unwrap();
        let lu = units_dir(live.path());
        let cu = units_dir(cand.path());
        write(&lu, "foo.target", "[Unit]\nRequires=a.service\n");
        write(&cu, "foo.target", "[Unit]\nRequires=b.service\n");
        let diff = compute_diff(live.path(), cand.path());
        assert!(diff.to_restart.is_empty() && diff.to_stop.is_empty());

        write(
            &lu,
            "foo.target",
            "[Unit]\nX-StopOnReconfiguration=true\nRequires=a.service\n",
        );
        write(
            &cu,
            "foo.target",
            "[Unit]\nX-StopOnReconfiguration=true\nRequires=b.service\n",
        );
        let diff = compute_diff(live.path(), cand.path());
        assert_eq!(diff.to_stop, vec!["foo.target"]);
    }

    #[test]
    fn changed_slice_is_noop() {
        let live = TempDir::new().unwrap();
        let cand = TempDir::new().unwrap();
        let lu = units_dir(live.path());
        let cu = units_dir(cand.path());
        write(&lu, "x.slice", "[Slice]\nMemoryMax=1G\n");
        write(&cu, "x.slice", "[Slice]\nMemoryMax=2G\n");
        let diff = compute_diff(live.path(), cand.path());
        assert!(diff.to_restart.is_empty() && diff.to_reload.is_empty() && diff.to_stop.is_empty());
    }

    // --- X-Reload-Triggers (§6.6) --------------------------------------

    #[test]
    fn reload_trigger_dir_change_restarts_and_marks_blanket() {
        let live = TempDir::new().unwrap();
        let cand = TempDir::new().unwrap();
        let lu = units_dir(live.path());
        let cu = units_dir(cand.path());
        // Identical unit file on both sides; only the trigger dir differs.
        let body = "[Unit]\nX-Reload-Triggers=/etc/sysctl.d\n[Service]\nExecStart=/bin/sysctl\n";
        write(&lu, "systemd-sysctl.service", body);
        write(&cu, "systemd-sysctl.service", body);
        // /etc/sysctl.d resolves under each /etc root.
        write(live.path(), "sysctl.d/10.conf", "a=1\n");
        write(cand.path(), "sysctl.d/10.conf", "a=1\n");
        write(cand.path(), "sysctl.d/70-new.conf", "b=2\n"); // gen-2 only

        let diff = compute_diff(live.path(), cand.path());
        assert_eq!(diff.to_restart, vec!["systemd-sysctl.service"]);
        assert_eq!(diff.blanket_targets, vec!["systemd-sysctl.service"]);
    }

    #[test]
    fn reload_trigger_with_exec_reload_reloads() {
        let live = TempDir::new().unwrap();
        let cand = TempDir::new().unwrap();
        let lu = units_dir(live.path());
        let cu = units_dir(cand.path());
        let body = "[Unit]\nX-ReloadIfChanged=true\nX-Reload-Triggers=/etc/nftables.d\n[Service]\nExecStart=/sbin/nft\nExecReload=/sbin/nft\n";
        write(&lu, "nftables.service", body);
        write(&cu, "nftables.service", body);
        write(cand.path(), "nftables.d/50.nft", "add element ...\n"); // candidate only

        let diff = compute_diff(live.path(), cand.path());
        assert_eq!(diff.to_reload, vec!["nftables.service"]);
        assert_eq!(diff.blanket_targets, vec!["nftables.service"]);
        assert!(diff.to_restart.is_empty());
    }

    #[test]
    fn identical_unit_with_unchanged_trigger_is_noop() {
        let live = TempDir::new().unwrap();
        let cand = TempDir::new().unwrap();
        let lu = units_dir(live.path());
        let cu = units_dir(cand.path());
        let body = "[Unit]\nX-Reload-Triggers=/etc/sysctl.d\n[Service]\nExecStart=/bin/sysctl\n";
        write(&lu, "systemd-sysctl.service", body);
        write(&cu, "systemd-sysctl.service", body);
        write(live.path(), "sysctl.d/10.conf", "a=1\n");
        write(cand.path(), "sysctl.d/10.conf", "a=1\n");
        let diff = compute_diff(live.path(), cand.path());
        assert!(diff.to_restart.is_empty() && diff.blanket_targets.is_empty());
    }

    // --- drop-ins -------------------------------------------------------

    #[test]
    fn dropin_only_unit_change_is_detected() {
        // No primary in /etc (systemd ships it under /usr/lib); only the
        // overrides.conf drop-in differs.
        let live = TempDir::new().unwrap();
        let cand = TempDir::new().unwrap();
        let lu = units_dir(live.path());
        let cu = units_dir(cand.path());
        write(
            &lu,
            "systemd-x.service.d/overrides.conf",
            "[Service]\nEnvironment=V=1\n",
        );
        write(
            &cu,
            "systemd-x.service.d/overrides.conf",
            "[Service]\nEnvironment=V=2\n",
        );
        let diff = compute_diff(live.path(), cand.path());
        assert_eq!(diff.to_restart, vec!["systemd-x.service"]);
    }

    #[test]
    fn dropin_reorder_changes_fingerprint() {
        let live = TempDir::new().unwrap();
        let cand = TempDir::new().unwrap();
        let lu = units_dir(live.path());
        let cu = units_dir(cand.path());
        write(&lu, "svc.service", "[Service]\nExecStart=/bin/true\n");
        write(&cu, "svc.service", "[Service]\nExecStart=/bin/true\n");
        // Same set of drop-ins, different override order → fingerprint differs.
        write(&lu, "svc.service.d/10-a.conf", "[Service]\nNice=1\n");
        write(&lu, "svc.service.d/20-b.conf", "[Service]\nNice=2\n");
        write(&cu, "svc.service.d/10-b.conf", "[Service]\nNice=2\n");
        write(&cu, "svc.service.d/20-a.conf", "[Service]\nNice=1\n");
        let diff = compute_diff(live.path(), cand.path());
        assert_eq!(diff.to_restart, vec!["svc.service"]);
    }

    // --- install symlinks ----------------------------------------------

    #[test]
    fn install_symlink_change_starts_unchanged_unit() {
        let live = TempDir::new().unwrap();
        let cand = TempDir::new().unwrap();
        let lu = units_dir(live.path());
        let cu = units_dir(cand.path());
        let body = "[Service]\nExecStart=/bin/true\n";
        write(&lu, "svc.service", body);
        write(&cu, "svc.service", body);
        // Candidate gains a multi-user.target.wants/svc.service symlink.
        std::fs::create_dir_all(cu.join("multi-user.target.wants")).unwrap();
        symlink(
            "../svc.service",
            cu.join("multi-user.target.wants/svc.service"),
        )
        .unwrap();

        let diff = compute_diff(live.path(), cand.path());
        assert_eq!(diff.install_only, vec!["svc.service"]);
        assert!(diff.to_restart.is_empty());
    }

    #[test]
    fn target_enablement_is_started_and_last_disablement_is_stopped() {
        let disabled = TempDir::new().unwrap();
        let enabled = TempDir::new().unwrap();
        let disabled_units = units_dir(disabled.path());
        let enabled_units = units_dir(enabled.path());
        let body = "[Unit]\nDescription=Package target\n";
        write(&disabled_units, "aos-pkg-web.target", body);
        write(&enabled_units, "aos-pkg-web.target", body);
        std::fs::create_dir_all(enabled_units.join("multi-user.target.wants")).unwrap();
        symlink(
            "../aos-pkg-web.target",
            enabled_units.join("multi-user.target.wants/aos-pkg-web.target"),
        )
        .unwrap();

        let enable = compute_diff(disabled.path(), enabled.path());
        assert_eq!(enable.install_only, vec!["aos-pkg-web.target"]);
        assert!(enable.to_stop.is_empty());

        let disable = compute_diff(enabled.path(), disabled.path());
        assert_eq!(disable.to_stop, vec!["aos-pkg-web.target"]);
        assert!(disable.install_only.is_empty());

        write(
            &disabled_units,
            "aos-pkg-web.target",
            "[Unit]\nDescription=Image package target\n",
        );
        let restore_image_unit = compute_diff(enabled.path(), disabled.path());
        assert_eq!(restore_image_unit.to_stop, vec!["aos-pkg-web.target"]);
        assert!(restore_image_unit.install_only.is_empty());

        let removed = TempDir::new().unwrap();
        std::fs::create_dir_all(units_dir(removed.path())).unwrap();
        let remove = compute_diff(enabled.path(), removed.path());
        assert_eq!(remove.to_stop, vec!["aos-pkg-web.target"]);
    }

    // --- masking --------------------------------------------------------

    #[test]
    fn masking_a_live_unit_stops_it() {
        let live = TempDir::new().unwrap();
        let cand = TempDir::new().unwrap();
        let lu = units_dir(live.path());
        let cu = units_dir(cand.path());
        write(&lu, "svc.service", "[Service]\nExecStart=/bin/true\n");
        symlink("/dev/null", cu.join("svc.service")).unwrap();
        let diff = compute_diff(live.path(), cand.path());
        assert_eq!(diff.to_stop, vec!["svc.service"]);
    }

    // --- socket activation (§6.7) --------------------------------------

    #[test]
    fn socket_map_and_socket_first_ordering() {
        let live = TempDir::new().unwrap();
        let cand = TempDir::new().unwrap();
        let lu = units_dir(live.path());
        let cu = units_dir(cand.path());
        // Both a socket and its service change, so both land in to_restart.
        write(&lu, "foo.socket", "[Socket]\nListenStream=/run/foo\n");
        write(&cu, "foo.socket", "[Socket]\nListenStream=/run/foo2\n");
        write(&lu, "foo.service", "[Service]\nExecStart=/bin/old\n");
        write(&cu, "foo.service", "[Service]\nExecStart=/bin/new\n");

        let diff = compute_diff(live.path(), cand.path());
        assert_eq!(
            diff.socket_map.get("foo.service"),
            Some(&vec!["foo.socket".to_string()])
        );
        // Socket must be restarted before the service.
        assert_eq!(diff.to_restart, vec!["foo.socket", "foo.service"]);
    }

    #[test]
    fn not_socket_activated_service_excluded_from_socket_map() {
        let live = TempDir::new().unwrap();
        let cand = TempDir::new().unwrap();
        units_dir(live.path());
        let cu = units_dir(cand.path());
        write(&cu, "foo.socket", "[Socket]\nListenStream=/run/foo\n");
        write(
            &cu,
            "foo.service",
            "[Unit]\nX-NotSocketActivated=true\n[Service]\nExecStart=/bin/true\n",
        );
        let diff = compute_diff(live.path(), cand.path());
        assert!(diff.socket_map.is_empty());
    }
}
