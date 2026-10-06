# The package repeats these actual-body differential proofs with its configured
# compiler. Native guest, snapshot, and fork qualification remain separate.
{
  pkgs,
  case,
}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  atomicPatch = import (patchDir + "/_atomic-patch.nix");
  baseline = import (patchDir + "/_native-costs-baseline.nix");
  baselineManifest = builtins.toFile "native-costs-baseline.json" (
    builtins.toJSON (builtins.removeAttrs baseline ["patch"])
  );
  # Catch prototype and declaration gaps before the configured package build.
  warningFlags = [
    "-Wall"
    "-Werror"
    "-Wmissing-prototypes"
    "-Wredundant-decls"
    "-Wstrict-prototypes"
    "-Wshadow=local"
    "-Wold-style-declaration"
    "-Wold-style-definition"
    "-Wnested-externs"
    "-Wundef"
    "-Wvla"
  ];
  check =
    if case == "mutex-waiter-counters"
    then "qemuMutexWaiterCounters"
    else if case == "tcg-page-collection"
    then "qemuTcgPageCollection"
    else throw "unsupported native cost proof: ${case}";
in
  pkgs.mkDerivation {
    pname = "crucible-phase1-qemu-${case}";
    version = "0";
    src = pkgs.qemu-crucible.src;

    buildDeps = [
      pkgs.coreutils
      pkgs.glib
      pkgs.glib.dev
      pkgs.grep
      pkgs.patch
      pkgs.python3
      pkgs.tar
      pkgs.xz
    ];

    phases = [
      {
        name = "unpack-and-apply-atomic-patch";
        script = ''
          set -eu
          tar -xf "$src"
          cd qemu-${atomicPatch.qemuVersion}
          patch --batch --forward --fuzz=0 -p1 -i "${patchDir}/${atomicPatch.file}"
        '';
      }
      {
        name = "run-native-differential-proof";
        script = ''
          set -eu
          export CC=cc
          export CFLAGS="-std=gnu11 -O2 ${builtins.concatStringsSep " " warningFlags} -I$PWD -I$PWD/include -I${pkgs.glib.dev}/include/glib-2.0 -I${pkgs.glib.dev}/lib/glib-2.0/include"
          export LDFLAGS="-L${pkgs.glib.dev}/lib -Wl,-rpath,${pkgs.glib}/lib -lglib-2.0"

          mkdir -p "$out"
          ${pkgs.python3}/bin/python3 ${./qemu-native-cost-proofs.py} \
            --case ${case} --source-root "$PWD" \
            --baseline-manifest ${baselineManifest} \
            --baseline-patch ${baseline.patch} \
            --output-dir "$out/proof" > "$out/production-proof.result"
          cat "$out/production-proof.result"
          grep -Fxq 'PASS production ${case}: differential observations and compiled causal negatives' \
            "$out/production-proof.result"

          cat > "$out/result" <<'RESULT'
          PASS
          check=checks.crucible.phase1.${check}
          baseline_revision=${baseline.revision}
          reconstructed_production_files_and_unchanged_header_sha256_verified=true
          native_observations_match_exact_prior_production_bodies=true
          compiled_causal_negative_controls_rejected=true
          bounded_provider_fixture_without_guest_execution=true
          RESULT
        '';
      }
    ];
  }
