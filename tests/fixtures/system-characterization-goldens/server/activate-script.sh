#!/nix/store/<HASH>-bash-5.2.37/bin/bash
# SPDX-License-Identifier: MIT
#
# modules/base/activate.sh.in — live install/upgrade/rollback driver.
#
# Built into `${toplevel}/activate` by `system.build.activateScript`
# (modules/base/build.nix), which substitutes the `@tool@` placeholders
# for absolute /nix/store paths. apm invokes it as `activate <gen>`
# before committing the `current → gen-N` profile pointer: it rebuilds this
# generation's /etc composefs overlay on the live system, reconciles running
# daemons across the swap, and swaps the new /etc in atomically.
#
# The Phase B-post swap (`mount --move --beneath` + recursive
# lazy-umount) is cribbed from NixOS switch-to-configuration:
#   nixpkgs nixos/modules/system/activation/ (activation-script /etc swap)
# Portions © 2003-2026 Eelco Dolstra and the Nixpkgs/NixOS contributors.
# Used under the MIT license; see nixpkgs' COPYING file for the full text.

set -euo pipefail
export LC_ALL=C
export PATH=

# --- Stage markers ---------------------------------------------------
# Which step is currently executing. The ERR trap reads $STAGE to pick
# the exit code and the cleanup action. $STAGE is reassigned as the
# script advances; only these constants are readonly.
declare -r STAGE_PREFLIGHT=preflight  # arg + env checks, before any mount
declare -r STAGE_PREPARE=prepare      # render the new gen's config lower
declare -r STAGE_COMPOSE=compose      # build the candidate /etc overlay
declare -r STAGE_PRESWAP=preswap      # stop old units + write reconcile plan
declare -r STAGE_SWAP=swap            # mount-move-beneath + lazy-umount of /etc
declare -r STAGE_POSTSWAP=postswap    # daemon-reload + apply reconcile plan
declare -r STAGE_CLEANUP=cleanup      # tear down the previous gen's mounts

# --- Exit codes ------------------------------------------------------
# The activate script's contract. preflight and compose are both "setup
# failed before any swap", so they share value 2; the two names keep
# each call site self-documenting.
declare -ri EX_OK=0         # all steps succeeded, every unit healthy
declare -ri EX_PREPARE=1    # prepare failed; no swap, previous gen live
declare -ri EX_PREFLIGHT=2  # bad args / missing env; no mounts yet
declare -ri EX_COMPOSE=2    # candidate overlay couldn't be built
declare -ri EX_RECONCILE=3  # pre-swap reconcile returned its catastrophic code
declare -ri EX_SWAP=4       # mount-move/lazy-umount failed; /etc indeterminate
declare -ri EX_CLEANUP=5    # prev-gen cleanup failed; the upgrade itself is fine
declare -ri EX_DEGRADED=6   # swap succeeded but reconcile reported failed units

# Set to 1 by the post-swap reconcile slot if units fail. The switch still
# stands (the swap is authoritative), but the final exit becomes EX_DEGRADED so
# apm surfaces a non-zero code.
reconcile_degraded=0

# Variables the cleanup fn references are declared during preflight so
# the trap can run even if a phase fails before assigning them.
STAGE="$STAGE_PREFLIGHT"

cleanup_partial_gen() {
  # Best-effort teardown of a half-built generation. All guarded with
  # `|| true` + `:-` so the trap never fails inside itself.
  #
  # The upper (/run/etc/upper-${N}/dir) is deliberately NOT removed. Uppers
  # are now persistent per-generation (see the compose stage), so when this
  # activation is a rollback INTO an existing gen N, wiping upper-N here would
  # destroy the runtime /etc writes preserved from N's earlier life this boot.
  # A leftover fresh-empty upper from a never-completed new gen is harmless;
  # upper lifetime is owned by generation GC and reboot (tmpfs), not this trap.
  /nix/store/<HASH>-util-linux-2.42.1/bin/umount --lazy "${sys:-/nonexistent}/metadata" 2>/dev/null || true
  /nix/store/<HASH>-util-linux-2.42.1/bin/umount --lazy "${sys:-/nonexistent}/content"  2>/dev/null || true
  /nix/store/<HASH>-coreutils-9.5/bin/rm -rf "/run/etc/system-${N:-_}" \
                         "/run/etc/config-${N:-_}" 2>/dev/null || true
}

on_err() {
  rc=$?
  # Quoted patterns are matched literally (no globbing), so each arm
  # fires when $STAGE equals the corresponding constant's value.
  case "$STAGE" in
    "$STAGE_PREFLIGHT") exit "$EX_PREFLIGHT" ;;        # no mounts yet
    "$STAGE_PREPARE")   cleanup_partial_gen; exit "$EX_PREPARE" ;;
    "$STAGE_COMPOSE")   cleanup_partial_gen; exit "$EX_COMPOSE" ;;
    "$STAGE_PRESWAP")   cleanup_partial_gen; exit "$EX_RECONCILE" ;;
    "$STAGE_SWAP")      echo "FATAL: /etc swap incomplete (rc=$rc)" >&2; exit "$EX_SWAP" ;;
    "$STAGE_POSTSWAP")  echo "WARN: post-swap step failed (rc=$rc); /etc swap stands" >&2; exit "$EX_DEGRADED" ;;
    "$STAGE_CLEANUP")
      # The swap already succeeded; a cleanup failure is cosmetic. If
      # reconcile also reported failed units, surface EX_DEGRADED (the
      # more important signal) rather than EX_CLEANUP.
      if [ "${reconcile_degraded:-0}" = 1 ]; then
        echo "WARN: prev-gen cleanup failed (rc=$rc); units also failed" >&2
        exit "$EX_DEGRADED"
      fi
      echo "WARN: prev-gen cleanup failed (rc=$rc)" >&2
      exit "$EX_CLEANUP" ;;
    *)                  exit "$EX_PREFLIGHT" ;;
  esac
}
trap on_err ERR

# --- preflight (STAGE is STAGE_PREFLIGHT from the header) ---
if [ $# -ne 1 ]; then
  echo "usage: activate <gen-number>" >&2
  exit "$EX_PREFLIGHT"
fi
N=$1
new_top=$(/nix/store/<HASH>-coreutils-9.5/bin/readlink /var/lib/profiles/system/gen-${N}/toplevel)

sys=/run/etc/system-${N}
ign=/run/etc/config-${N}
# Declared in preflight (not Phase B-pre) so cleanup_partial_gen can
# reference it if Phase A fails before the tmpfs is mounted.
upper_root=/run/etc/upper-${N}

# Determine the config backend for this generation's per-host /etc.
#
# Legacy Ignition path: /run/ignition/platform.env is written at first boot by
# aos-platform-detect into the initrd's /run (which systemd-initrd moves to
# stage-2's /run across switch_root), so per-host /etc is rendered by re-running
# ignition's fetch+files stages below.
#
# Per-host
# /etc comes from the on-host config-eval manifest (/run/aos/manifest.json),
# applied by `apm __materialize` below. When neither is present the generation's
# /etc is exactly the baked image /etc. Detect the path by the presence of
# platform.env.
ignition_active=0
if [ -r /run/ignition/platform.env ]; then
  ignition_active=1
  . /run/ignition/platform.env
fi

/nix/store/<HASH>-coreutils-9.5/bin/mkdir -p /run/apm
/nix/store/<HASH>-coreutils-9.5/bin/chmod 0700 /run/apm
exec {LOCK_FD}>/run/apm/switch.lock
if ! /nix/store/<HASH>-util-linux-2.42.1/bin/flock -n "$LOCK_FD"; then
  echo "activate: another system switch holds /run/apm/switch.lock" >&2
  exit "$EX_PREFLIGHT"
fi

# Warn if the currently-live generation has runtime /etc writes in its
# overlay upper that aren't backed by the /var/etc allowlist. Per-gen
# uppers persist for the life of the boot, so these writes stay with the
# current generation (and are restored if it is re-activated this boot) but
# do NOT follow the switch into gen $N. A dirty upper usually means some
# process wrote under /etc outside the persistence allowlist; the durable
# fix is to add the path to /var/etc (storage.links), not to lean on the
# ephemeral upper. Detection uses bash globbing (nullglob+dotglob) so it
# needs no external tool; any immediate child of dir/ — file, subdir, or
# overlay whiteout — counts as dirty.
cur_upper=$(/nix/store/<HASH>-coreutils-9.5/bin/readlink -f /run/etc/upper 2>/dev/null || true)
if [ -n "$cur_upper" ] && [ -d "$cur_upper/dir" ]; then
  shopt -s nullglob dotglob
  cur_writes=("$cur_upper"/dir/*)
  shopt -u nullglob dotglob
  if [ "${#cur_writes[@]}" -gt 0 ]; then
    echo "activate: WARNING: the live generation's /etc overlay upper" >&2
    echo "activate:   ($cur_upper/dir) holds ${#cur_writes[@]} runtime write(s)" >&2
    echo "activate:   not captured in /var/etc. They stay with that generation" >&2
    echo "activate:   (restored if you switch back to it this boot) but do NOT" >&2
    echo "activate:   carry into gen $N. Persist anything that must survive via" >&2
    echo "activate:   the /var/etc allowlist (storage.links)." >&2
  fi
fi

# --- prepare ---
# From here a failure maps to activate exit 1 (EX_PREPARE): the ERR trap
# tears down the partial generation and the previous gen stays live.
STAGE="$STAGE_PREPARE"

# Belt-and-suspenders: re-mount the userdata ISO if it's gone. (The
# systemd auto-cleanup of /run mounts is bounded by the lifetime of the
# mounting unit; if the metadata mount was reaped, restore it here so
# ignition's file provider can read /run/aos-metadata/config.json.)
# `ignition_active` short-circuits before $PLATFORM_ID is referenced, so this is
# safe under `set -u` when platform.env is never sourced.
if [ "$ignition_active" = 1 ] && [ "$PLATFORM_ID" = "file" ] && \
   ! /nix/store/<HASH>-util-linux-2.42.1/bin/mountpoint -q /run/aos-metadata; then
  /nix/store/<HASH>-coreutils-9.5/bin/mkdir -p /run/aos-metadata
  /nix/store/<HASH>-util-linux-2.42.1/bin/mount -t iso9660 -o ro,nodev,nosuid \
    /dev/disk/by-label/aos-metadata /run/aos-metadata
fi

/nix/store/<HASH>-coreutils-9.5/bin/mkdir -p "$sys/metadata" "$sys/content" "$ign/etc"
/nix/store/<HASH>-util-linux-2.42.1/bin/mount --bind \
  "$new_top/etc-basedir" "$sys/content"
/nix/store/<HASH>-util-linux-2.42.1/bin/mount -t erofs -o ro,nodev,nosuid \
  "$new_top/etc-metadata.erofs" "$sys/metadata"

# Render this generation's per-host /etc writes into the candidate lower
# ($ign/etc). Two mutually exclusive backends:
#
#   * Legacy Ignition path (platform.env present): re-run ignition's fetch +
#     files stages. A fresh --config-cache avoids colliding with the first-boot
#     /run/ignition.json. IGNITION_CONFIG_FILE is forwarded for `platform=file`
#     (carries /run/aos-metadata/config.json). `env -i` clears the environment;
#     the absolute path avoids relying on the PATH we cleared.
#
#   * a converged config-eval manifest exists: apply it with
#     `apm __materialize`, which writes the manifest's text/symlink /etc entries
#     and job scripts into $ign/etc and rewrites unit-body job-script
#     placeholders. When neither backend fires, $ign/etc stays empty and the
#     generation's /etc is exactly the baked image /etc.
if [ "$ignition_active" = 1 ]; then
  /nix/store/<HASH>-coreutils-9.5/bin/env -i \
      PLATFORM_ID="$PLATFORM_ID" \
      IGNITION_CONFIG_FILE="${IGNITION_CONFIG_FILE:-}" \
      PATH="/nix/store/<HASH>-coreutils-9.5/bin" \
    /nix/store/<HASH>-ignition-2.25.1/bin/ignition --root="$ign" \
                            --config-cache="/run/aos-ignition-$N.json" \
                            --platform="$PLATFORM_ID" --stage=fetch \
                            --log-to-stdout
  /nix/store/<HASH>-coreutils-9.5/bin/env -i \
      PLATFORM_ID="$PLATFORM_ID" \
      IGNITION_CONFIG_FILE="${IGNITION_CONFIG_FILE:-}" \
      PATH="/nix/store/<HASH>-coreutils-9.5/bin" \
    /nix/store/<HASH>-ignition-2.25.1/bin/ignition --root="$ign" \
                            --config-cache="/run/aos-ignition-$N.json" \
                            --platform="$PLATFORM_ID" --stage=files \
                            --log-to-stdout
elif [ -f /run/aos/manifest.json ]; then
  /nix/store/<HASH>-aos-0.1.0/bin/apm __materialize \
    --manifest /run/aos/manifest.json \
    --etc-root "$ign/etc"
fi

# --- compose ---
# From here a failure maps to activate exit 2 (EX_COMPOSE: the candidate
# overlay couldn't be built); the ERR trap cleans up and the previous
# gen stays live.
STAGE="$STAGE_COMPOSE"

# $upper_root was declared during preflight. Create the upper + work dirs
# as plain directories inside the /run/etc tmpfs — there is no dedicated
# per-gen tmpfs mount: the parent /run/etc is already tmpfs (nosuid,nodev,
# mode=755), so a subdirectory inherits the same backing and flags. This
# also matches how the boot path (etc-overlay-setup.service) creates it.
#
# `mkdir -p` is deliberately content-preserving. Per-generation uppers are
# NOT torn down on switch-away (see the cleanup stage), so re-activating a
# generation this boot — a rollback or a roll-forward — reuses the upper it
# left behind and restores that generation's runtime /etc writes. A gen
# never activated this boot has no upper-<N> yet, so it starts empty,
# matching fresh-boot semantics. Persistent host state still lives in
# /var/etc (a shared lower in every generation's overlay); the upper holds
# only writes that escaped that allowlist, and it is wiped on reboot
# (tmpfs) regardless.
/nix/store/<HASH>-coreutils-9.5/bin/mkdir -p "$upper_root/dir" "$upper_root/work"

tmpEtc=$(/nix/store/<HASH>-coreutils-9.5/bin/mktemp -d -p /run aos-etc-final.XXXXXX)
/nix/store/<HASH>-util-linux-2.42.1/bin/mount --bind --make-private "$tmpEtc" "$tmpEtc"

# The overlay option string must contain no spaces; the continuation
# lines below are intentionally NOT indented so the `\`-joined value
# stays comma-separated with no embedded whitespace.
/nix/store/<HASH>-util-linux-2.42.1/bin/mount -t overlay overlay -o \
nodev,nosuid,metacopy=on,redirect_dir=on,\
lowerdir+=/var/etc,\
lowerdir+="$ign/etc",\
lowerdir+="$sys/metadata",\
datadir+="$sys/content",\
upperdir="$upper_root/dir",\
workdir="$upper_root/work" \
  "$tmpEtc"

# --- pre-swap reconcile ---
# Hand off to apm before the swap: diff live /etc against the candidate, stop
# old-definition units, and capture the post-swap plan path. The path is the
# command's only stdout; diagnostics go to stderr via Printer.
STAGE="$STAGE_PRESWAP"
set +e
# Invoke the UNWRAPPED binary directly, not /nix/store/<HASH>-aos-0.1.0/bin/apm. The `apm` wrapper
# runs `exec "$(dirname "$0")/.apm-unwrapped"`, which needs `dirname` on PATH —
# but this script runs with `PATH=` (empty), so the wrapper would die with
# "dirname: command not found". The activate subcommands do pure filesystem +
# D-Bus work and shell out to neither git nor nix-store, so they need none of
# the git/nix PATH the wrapper sets up.
plan=$(/nix/store/<HASH>-aos-0.1.0/bin/.apm-unwrapped activate-pre-etc-swap \
  --gen="$N" \
  --candidate-etc="$tmpEtc")
pre_rc=$?
set -e

case "$pre_rc" in
  0) ;;                                              # proceed; $plan is the plan path
  *) cleanup_partial_gen; exit "$EX_RECONCILE" ;;    # catastrophic → abort before swap
esac
trap '[ -n "${plan:-}" ] && /nix/store/<HASH>-coreutils-9.5/bin/rm -f "$plan" 2>/dev/null || true' EXIT

# --- swap ---
# From here a failure maps to activate exit 4 (EX_SWAP): the swap is in
# progress, so an error leaves /etc in an indeterminate state and the
# ERR trap does NOT attempt cleanup — it only logs loudly. Operator
# intervention is expected in that case.
STAGE="$STAGE_SWAP"

# Carry any existing submounts under /etc into the new mount. (Operators
# may have manually mounted things under /etc — e.g. a /etc/secrets
# bind-mount from an encrypted volume. We preserve those.)
/nix/store/<HASH>-util-linux-2.42.1/bin/findmnt /etc --submounts --list \
  --noheading --kernel --output TARGET |
while read -r mountPoint; do
  [ "$mountPoint" = /etc ] && continue
  tmp="$tmpEtc/${mountPoint#/etc/}"
  [ -d "$mountPoint" ] && /nix/store/<HASH>-coreutils-9.5/bin/mkdir -p "$tmp"
  [ -f "$mountPoint" ] && /nix/store/<HASH>-coreutils-9.5/bin/touch  "$tmp"
  /nix/store/<HASH>-util-linux-2.42.1/bin/mount --bind "$mountPoint" "$tmp"
done

# `mount --move --beneath` requires util-linux 2.42.1+ (pinned in
# pkgs/tools/util-linux.nix). It slips the new /etc mount beneath the
# old, then the recursive lazy-umount drops the old; open fds on the old
# layer survive until their holders close them, so daemons that
# reconcile land on the new view and the rest drain naturally.
/nix/store/<HASH>-util-linux-2.42.1/bin/mount --move --beneath "$tmpEtc" /etc
/nix/store/<HASH>-util-linux-2.42.1/bin/umount --lazy --recursive /etc
/nix/store/<HASH>-util-linux-2.42.1/bin/umount --lazy "$tmpEtc"
/nix/store/<HASH>-coreutils-9.5/bin/rmdir "$tmpEtc"

# Retarget inspection symlinks.
prev_gen=$(/nix/store/<HASH>-coreutils-9.5/bin/readlink /run/etc/system \
           | /nix/store/<HASH>-coreutils-9.5/bin/cut -d- -f2-)
/nix/store/<HASH>-coreutils-9.5/bin/ln -sfn system-${N}   /run/etc/system
/nix/store/<HASH>-coreutils-9.5/bin/ln -sfn config-${N} /run/etc/config
/nix/store/<HASH>-coreutils-9.5/bin/ln -sfn upper-${N}    /run/etc/upper

# --- post-swap reconcile ---
# The /etc swap is now the commit point. Any post-swap reconcile problem is
# reported as degraded, never as a rollback/cleanup of the new live /etc.
STAGE="$STAGE_POSTSWAP"
set +e
/nix/store/<HASH>-aos-0.1.0/bin/.apm-unwrapped activate-post-etc-swap --plan="$plan"
post_rc=$?
set -e

case "$post_rc" in
  0) ;;
  *) reconcile_degraded=1
     echo "activate: post-swap reconcile reported failures (rc=$post_rc); switch stands" >&2 ;;
esac

# --- cleanup ---
# The swap already succeeded; a failure here is cosmetic (stale mounts),
# so STAGE_CLEANUP makes the ERR trap log a warning and exit EX_CLEANUP
# (5) — or EX_DEGRADED (6) if reconcile also reported failed units. apm
# maps 5 to a successful upgrade.
STAGE="$STAGE_CLEANUP"

# Tear down the previous generation's LOWER stack only (EROFS metadata +
# content bind, and the rendered config lower). These are rebuilt from the
# toplevel by the prepare stage on every activation, so a later switch back
# to $prev_gen reconstructs them cheaply.
#
# The previous gen's upper (/run/etc/upper-${prev_gen}) is deliberately
# PRESERVED — uppers are per-generation and persist for the life of the boot
# so switching back restores that gen's runtime /etc writes. Nothing is
# unmounted for the upper either: it is a plain directory in the /run/etc
# tmpfs now, not its own mount. Stale uppers are reclaimed by generation GC
# (when apm prunes the generation) and by reboot (tmpfs), never here.
if [ -n "${prev_gen:-}" ] && [ "$prev_gen" != "$N" ]; then
  /nix/store/<HASH>-util-linux-2.42.1/bin/umount --lazy "/run/etc/system-${prev_gen}/metadata" || true
  /nix/store/<HASH>-util-linux-2.42.1/bin/umount --lazy "/run/etc/system-${prev_gen}/content"  || true
  /nix/store/<HASH>-coreutils-9.5/bin/rm -rf "/run/etc/system-${prev_gen}" \
                         "/run/etc/config-${prev_gen}"
fi

# All phases succeeded. If reconcile reported failed units the switch
# still stands, but exit EX_DEGRADED so apm surfaces a non-zero code.
if [ "${reconcile_degraded:-0}" = 1 ]; then
  exit "$EX_DEGRADED"
fi
exit "$EX_OK"
