{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.gates.patchMicrotests",
  taskIds ? ["T-HARN-20" "T-PATCH-2"],
}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  qemuNix = builtins.readFile ../../pkgs/emulation/qemu.nix;
  defaultNix = builtins.readFile ./default.nix;
  qemuPatchSeries = import ./phase2-qemu-patch-series.nix {inherit pkgs lib;};
  qemuPackage = pkgs.qemu-crucible;
  patchFiles =
    builtins.sort builtins.lessThan
    (builtins.filter
      (name: lib.hasSuffix ".patch" name)
      (builtins.attrNames (builtins.readDir patchDir)));

  perPatchMicrotests = [
    {
      patch = "0001-crucible-rr-fingerprint-helpers.patch";
      check = import ./phase1-rr-fingerprint-helpers.nix {inherit pkgs lib qemuPackage;};
    }
    {
      patch = "0002-crucible-icount-no-realtime.patch";
      check = import ./phase1-icount-no-realtime.nix {inherit pkgs lib qemuPackage;};
    }
    {
      patch = "0003-crucible-no-warp-with-plugin.patch";
      check = import ./phase1-no-warp-with-plugin.nix {inherit pkgs lib qemuPackage;};
    }
    {
      patch = "0004-crucible-det-glib-prng.patch";
      check = import ./phase1-qemu-deterministic-entropy.nix {inherit pkgs lib qemuPackage;};
    }
    {
      patch = "0005-crucible-clock-deadline.patch";
      check = import ./phase1-clock-deadline.nix {inherit pkgs lib qemuPackage;};
    }
  ];

  microtestPatchNames =
    builtins.sort builtins.lessThan (map (test: test.patch) perPatchMicrotests);

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

  missingMicrotests =
    builtins.filter (patch: !(builtins.elem patch microtestPatchNames)) patchFiles;
  staleMicrotests =
    builtins.filter (patch: !(builtins.elem patch patchFiles)) microtestPatchNames;
  unwiredPatches =
    builtins.filter
    (patch: !(hasInfix "patch -p1 < \${./qemu-patches/${patch}}" qemuNix))
    patchFiles;
  qemuInertGateUnwired = !(
    hasInfix "qemuInert = redGate {" defaultNix
    && hasInfix ''gateName = "gate:qemu-inert";'' defaultNix
    && hasInfix "dependencies = [patchMicrotestsCheck];" defaultNix
    && hasInfix "patchMicrotests = patchMicrotestsCheck;" defaultNix
  );

  staticFailures =
    map (patch: "pkgs/emulation/qemu-patches/${patch}: carried patch has no per-patch micro-test")
    missingMicrotests
    ++ map (patch: "tests/crucible/phase2-patch-microtests.nix: stale micro-test for absent patch ${patch}")
    staleMicrotests
    ++ map (patch: "pkgs/emulation/qemu.nix: carried patch is not applied by the QEMU package: ${patch}")
    unwiredPatches
    ++ lib.optionals qemuInertGateUnwired [
      "tests/crucible/default.nix: phase2 gate:qemu-inert is not wired into the patch CI dependency surface"
    ];

  resultChecks = lib.concatMapStringsSep "\n" (test: ''
    result="${test.check}/result"
    cp "$result" "$out/per-patch/${test.patch}.result"
    grep -q '^PASS$' "$result"
    grep -q '^gate=gate:patch-microtests$' "$result"
    grep -q '^patch=${test.patch}$' "$result"
    grep -q '^patched_fixture_exercised=true$' "$result"
    grep -q '^stock_negative_control=true$' "$result"
    grep -q '^qemu_package=${qemuPackage}$' "$result"
    grep -q '^qemu_package_version=${qemuPackage.version}$' "$result"
  '')
  perPatchMicrotests;
in
  if staticFailures != []
  then throw "crucible phase2 patch-microtests gate failed:\n${builtins.concatStringsSep "\n" staticFailures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-patch-microtests";
      version = "0";
      src = null;

      buildDeps = [
        pkgs.coreutils
        pkgs.grep
        pkgs.patch
        pkgs.tar
        pkgs.xz
      ];

      phases = [
        {
          name = "aggregate-patch-microtests";
          script = ''
            set -eu

            mkdir -p "$out/per-patch"

            work_dir="$PWD"
            apply_dir="$TMPDIR/qemu-patch-apply-clean"
            mkdir -p "$apply_dir"
            tar -xf ${qemuPackage.src} -C "$apply_dir"
            cd "$apply_dir/qemu-${qemuPackage.version}"
            for patch in ${builtins.concatStringsSep " " patchFiles}; do
              patch --batch --forward --fuzz=0 -p1 -i "${patchDir}/$patch"
            done
            cd "$work_dir"

            test -x ${qemuPackage}/bin/qemu-system-x86_64
            test -f ${qemuPackage}/include/qemu/qemu-plugin.h

            cp "${qemuPatchSeries}/result" "$out/patch-series.result"
            grep -q '^PASS$' "$out/patch-series.result"

            ${resultChecks}

            cat > "$out/result" <<'RESULT'
            PASS
            check=${attrPath}
            tasks=${builtins.concatStringsSep "," taskIds}
            gate=gate:patch-microtests
            patch_count=${toString (builtins.length patchFiles)}
            microtest_count=${toString (builtins.length perPatchMicrotests)}
            patches=${builtins.concatStringsSep "," patchFiles}
            patch_series_gate_passed=true
            apply_clean_pinned_qemu=true
            apply_clean_patch_fuzz=0
            patched_qemu_package_build_passed=true
            patched_qemu_package=${qemuPackage}
            patched_qemu_package_version=${qemuPackage.version}
            qemu_inert_gate_attr=checks.crucible.phase2.gates.qemuInert
            qemu_inert_gate_wired=true
            qemu_inert_depends_on_patch_microtests=true
            qemu_inert_gate_dependency=gate:qemu-inert->gate:patch-microtests
            qemu_inert_full_corpus_task=T-PATCH-3
            every_carried_patch_has_microtest=true
            every_microtest_keyed_to_patched_qemu_package=true
            every_microtest_exercises_patched_fixture=true
            every_microtest_has_stock_negative_control=true
            qemu_package_applies_every_carried_patch=true
            RESULT
          '';
        }
      ];
    }
