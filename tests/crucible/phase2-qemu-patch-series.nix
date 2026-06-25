{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuPatchSeries",
  taskIds ? ["T-PATCH-1"],
}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  qemuNix = builtins.readFile ../../pkgs/emulation/qemu.nix;
  qemuPatchSpec = builtins.readFile ../../docs/rfcs/0010-crucible/11-qemu-patches.md;
  packagingSpec = builtins.readFile ../../docs/rfcs/0010-crucible/26-packaging-aos-integration.md;

  patchFiles =
    builtins.sort builtins.lessThan
    (builtins.filter
      (name: lib.hasSuffix ".patch" name)
      (builtins.attrNames (builtins.readDir patchDir)));

  carriedPatches = [
    {
      file = "0001-crucible-sim-accel.patch";
      catalogName = "crucible-sim-accel";
      class = "D";
      enforces = "DET-1,TIME-23,E14";
      capability = "-accel sim deterministic TCG accelerator";
    }
    {
      file = "0002-crucible-rr-fingerprint-helpers.patch";
      catalogName = "crucible-rr-fingerprint-helpers";
      class = "F";
      enforces = "DET-29,QEMU-43";
      capability = "phase1 RR quantum and fingerprint helper ABI";
    }
    {
      file = "0003-crucible-icount-no-realtime.patch";
      catalogName = "crucible-icount-no-realtime";
      class = "D";
      enforces = "DET-9,TIME-22,E3";
      capability = "sim precise icount budget excludes realtime deadlines";
    }
    {
      file = "0004-crucible-no-warp-with-plugin.patch";
      catalogName = "crucible-no-warp-with-plugin";
      class = "D";
      enforces = "DET-10,TIME-21,E2";
      capability = "sim time-control plugin suppresses idle wall-clock warp";
    }
    {
      file = "0005-crucible-det-glib-prng.patch";
      catalogName = "crucible-det-glib-prng";
      class = "D";
      enforces = "DET-21,E9";
      capability = "run seed initializes QEMU global GLib PRNG";
    }
    {
      file = "0006-crucible-clock-deadline.patch";
      catalogName = "crucible-clock-deadline";
      class = "D";
      enforces = "TIME-24,TIME-25";
      capability = "plugin-visible exact next virtual timer deadline";
    }
    {
      file = "0007-crucible-block-rtc-read.patch";
      catalogName = "crucible-block-rtc-read";
      class = "D";
      enforces = "DET-8,TIME-20,E5";
      capability = "sim RTC and realtime reads use fixed epoch plus virtual time";
    }
    {
      file = "0008-crucible-det-getrandom.patch";
      catalogName = "crucible-det-getrandom";
      class = "D";
      enforces = "DET-21,DET-19,E9";
      capability = "sim unseeded guest-random fails closed before host crypto";
    }
    {
      file = "0009-crucible-net-deterministic.patch";
      catalogName = "crucible-net-deterministic";
      class = "D";
      enforces = "DET-11,DET-13,E18";
      capability = "plugin-chosen icount network RX injection and flush";
    }
    {
      file = "0010-crucible-plugin-time-advance.patch";
      catalogName = "crucible-plugin-time-advance";
      class = "D";
      enforces = "TIME-23,TIME-27,DET-1,INV-10";
      capability = "plugin-owned synchronous virtual-time advance and BH/main-loop drains";
    }
    {
      file = "0011-crucible-plugin-icount-raw.patch";
      catalogName = "crucible-plugin-icount-raw";
      class = "F";
      enforces = "DET-29,INV-10";
      capability = "plugin-visible raw bias-excluded icount read";
    }
    {
      file = "0012-crucible-plugin-vcpu-exit.patch";
      catalogName = "crucible-plugin-vcpu-exit";
      class = "D";
      enforces = "DET-1,INV-10";
      capability = "plugin force vCPU exit for first-exit phase normalization";
    }
    {
      file = "0013-crucible-plugin-wake-fd.patch";
      catalogName = "crucible-plugin-wake-fd";
      class = "F";
      enforces = "SHM-26,INV-8";
      capability = "plugin wake fd registration and blocking main-loop wait";
    }
    {
      file = "0014-crucible-plugin-tcg-exec-cb.patch";
      catalogName = "crucible-plugin-tcg-exec-cb";
      class = "F";
      enforces = "coverage,INV-7";
      capability = "post-tcg_cpu_exec coverage callback with disabled NULL-check";
    }
    {
      file = "0015-crucible-blk-shmem.patch";
      catalogName = "crucible-blk-shmem";
      class = "F";
      enforces = "PATCH-26,E19";
      capability = "crucible-shmem block driver and plugin submit/poll callback ABI";
    }
    {
      file = "0016-crucible-blk-shmem-io-fixes.patch";
      catalogName = "crucible-blk-shmem-io-fixes";
      class = "D";
      enforces = "PATCH-27,E19";
      capability = "bounded coroutine reschedule cadence for deterministic block completions";
    }
    {
      file = "0017-crucible-blk-write-sentinel.patch";
      catalogName = "crucible-blk-write-sentinel";
      class = "D";
      enforces = "PATCH-28,E19";
      capability = "pending sentinel distinct from zero-length success";
    }
    {
      file = "0018-crucible-dev-cb-api.patch";
      catalogName = "crucible-dev-cb-api";
      class = "F";
      enforces = "PATCH-30,PLUG,SHM-17";
      capability = "plugin 9p burst/submit/poll callback registration ABI";
    }
    {
      file = "0019-crucible-9p-shmem.patch";
      catalogName = "crucible-9p-shmem";
      class = "F";
      enforces = "PATCH-29,E19";
      capability = "virtio-9p raw-message shmem forwarding path with upstream fallback";
    }
  ];

  carriedPatchFiles = map (patch: patch.file) carriedPatches;

  hasInfix = needle: haystack: let
    needleLen = builtins.stringLength needle;
    haystackLen = builtins.stringLength haystack;
    maxStart = haystackLen - needleLen;
    indexes =
      if needleLen == 0
      then [0]
      else if maxStart < 0
      then []
      else builtins.genList (index: index) (maxStart + 1);
  in
    builtins.any (index:
      builtins.substring index needleLen haystack == needle)
    indexes;

  missingCarriedPatches =
    builtins.filter (patch: !(builtins.elem patch patchFiles)) carriedPatchFiles;
  unmanifestedPatches =
    builtins.filter (patch: !(builtins.elem patch carriedPatchFiles)) patchFiles;
  unwiredPatches =
    builtins.filter
    (patch: !(hasInfix "patch -p1 < \${./qemu-patches/${patch}}" qemuNix))
    carriedPatchFiles;
  uncatalogedPatches =
    builtins.filter
    (patch: !(hasInfix patch.catalogName qemuPatchSpec))
    carriedPatches;

  failures =
    map (patch: "tests/crucible/phase2-qemu-patch-series.nix: manifest references absent patch ${patch}")
    missingCarriedPatches
    ++ map (patch: "pkgs/emulation/qemu-patches/${patch}: carried patch is absent from the T-PATCH-1 manifest")
    unmanifestedPatches
    ++ map (patch: "pkgs/emulation/qemu.nix: carried patch is not applied by the QEMU package: ${patch}")
    unwiredPatches
    ++ map (patch: "docs/rfcs/0010-crucible/11-qemu-patches.md: catalog missing carried patch name ${patch.catalogName}")
    uncatalogedPatches
    ++ lib.optionals (!(hasInfix ''version = "10.0.0";'' qemuNix)) [
      "pkgs/emulation/qemu.nix: QEMU pin must be 10.0.0 for this carried series"
    ]
    ++ lib.optionals (!(hasInfix ''hash = "sha256-IsB1YB/c+MeyZxqDnr3O8dTylz62c1JU/S4b0PMLOJY=";'' qemuNix)) [
      "pkgs/emulation/qemu.nix: QEMU 10.0.0 source hash is not the recorded pin"
    ]
    ++ lib.optionals (!(hasInfix "pinned minimum QEMU version of 10.0 or" qemuPatchSpec)) [
      "docs/rfcs/0010-crucible/11-qemu-patches.md: PATCH-40 QEMU >=10.0 requirement missing"
    ]
    ++ lib.optionals (!(hasInfix "The pinned QEMU version MUST be" packagingSpec && hasInfix "10.0" packagingSpec)) [
      "docs/rfcs/0010-crucible/26-packaging-aos-integration.md: PKG-9 QEMU >=10.0 requirement missing"
    ];

  manifestLines =
    lib.concatMapStringsSep "\n" (patch: ''
      echo "patch=${patch.file}"
      echo "catalog_name=${patch.catalogName}"
      echo "class=${patch.class}"
      echo "enforces=${patch.enforces}"
      echo "capability=${patch.capability}"
      echo
    '')
    carriedPatches;
in
  if failures != []
  then throw "crucible phase2 QEMU patch-series conformance failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-patch-series";
      version = "0";
      src = null;

      buildDeps = [
        pkgs.coreutils
        pkgs.gawk
        pkgs.grep
      ];

      phases = [
        {
          name = "check-qemu-patch-series";
          script = ''
            set -eu

            fail() {
              echo "FAIL: $*" >&2
              exit 1
            }

            mkdir -p "$out"

            for patch in ${builtins.concatStringsSep " " carriedPatchFiles}; do
              case "$patch" in
                [0-9][0-9][0-9][0-9]-crucible-*.patch) ;;
                *) fail "patch name is not stable NNNN-crucible-*.patch: $patch" ;;
              esac

              file="${patchDir}/$patch"
              [ -f "$file" ] || fail "missing patch file: $patch"

              if grep -E '^\+.*(crucible-replay-start|replay_configure|replay_add|replay_save|replay_read|REPLAY_MODE_RECORD|REPLAY_MODE_PLAY)' "$file"; then
                fail "record/replay-start scaffolding added by $patch"
              fi
            done

            cat > "$out/manifest" <<'MANIFEST'
            ${manifestLines}
            MANIFEST

            awk '
              /^patch=/ { patch = $0 }
              /^class=/ {
                if ($0 != "class=D" && $0 != "class=F") {
                  printf "bad patch class after %s: %s\n", patch, $0 > "/dev/stderr"
                  exit 1
                }
              }
              /^enforces=/ {
                if ($0 == "enforces=") {
                  printf "missing invariant after %s\n", patch > "/dev/stderr"
                  exit 1
                }
              }
            ' "$out/manifest"

            cat > "$out/result" <<'RESULT'
            PASS
            check=${attrPath}
            tasks=${builtins.concatStringsSep "," taskIds}
            qemu_version=10.0.0
            qemu_minimum_version_satisfied=true
            qemu_source_hash=sha256-IsB1YB/c+MeyZxqDnr3O8dTylz62c1JU/S4b0PMLOJY=
            gate=gate:patch-series
            carried_patch_count=${toString (builtins.length carriedPatches)}
            patches=${builtins.concatStringsSep "," carriedPatchFiles}
            stable_numeric_crucible_patch_names=true
            significant_order_is_manifested=true
            every_carried_patch_has_class=true
            every_carried_patch_has_invariant_or_capability=true
            qemu_package_applies_manifested_series=true
            record_replay_start_scaffolding_absent=true
            RESULT
          '';
        }
      ];
    }
