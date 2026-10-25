##! Qualifies the boot-identity production builder and its rustc rollback.
{pkgs}: let
  ordinary = pkgs.aos-boot-identity;
  candidate = ordinary.passthru.withBuildDriver "bazel";
  build = candidate.passthru.bazelBuild;
  source = ../../crates/boot/aos-boot-identity;
in rec {
  inherit candidate;
  driver-selection = assert ordinary.passthru.buildDriver == "rustc";
  assert candidate.passthru.buildDriver == "bazel";
  assert candidate.passthru.rustcFallback.drvPath == ordinary.drvPath;
  assert (candidate.passthru.withBuildDriver "rustc").drvPath == ordinary.drvPath;
  assert !(builtins.tryEval ((ordinary.passthru.withBuildDriver "invalid").drvPath)).success;
  assert candidate.platformSupport == ordinary.platformSupport;
  assert candidate.module == ordinary.module;
  assert candidate.moduleDeps == ordinary.moduleDeps;
  assert candidate.runtimeDeps == ordinary.runtimeDeps;
    pkgs.runCommand "aos-bazel-boot-identity-driver-selection" {} ''
      mkdir -p "$out"
      printf 'PASS\n' > "$out/result"
    '';
  parity =
    pkgs.runCommand "aos-bazel-boot-identity-production-parity" {
      buildDeps = [pkgs.rust pkgs.python3 pkgs.binutils];
    } ''
      mkdir -p "$out"
      rustc --edition=2024 --crate-name aos_boot_identity --crate-type rlib \
        ${source}/src/lib.rs -o libaos_boot_identity.rlib
      rustc --edition=2024 --test ${source}/src/lib.rs -o unit-tests
      ./unit-tests > "$out/native-unit.log"
      for driver in ordinary bazel; do
        case "$driver" in
          ordinary) binary=${ordinary}/bin/aos-boot-identity ;;
          bazel) binary=${candidate}/bin/aos-boot-identity ;;
        esac
        env CARGO_BIN_EXE_aos-boot-identity="$binary" \
          rustc --edition=2024 --test ${source}/tests/uki_cli.rs \
            --extern aos_boot_identity=libaos_boot_identity.rlib -o "$driver-cli-tests"
        env -u LD_LIBRARY_PATH "./$driver-cli-tests" > "$out/$driver-cli-tests.log"
      done
      ${pkgs.python3}/bin/python3 - <<'PY'
      import json
      from pathlib import Path

      Path("oracles.json").write_text(json.dumps({
          "//crates/boot/aos-boot-identity:unit": str(Path("unit-tests").resolve()),
          "//crates/boot/aos-boot-identity:uki_cli": str(Path("ordinary-cli-tests").resolve()),
      }))
      PY
      ${pkgs.python3}/bin/python3 ${../../tools/bazel/tests/verify_pilot.py} \
        --tests ${build}/evidence/tests --oracles oracles.json --output "$out/test-parity.json"
      ${pkgs.python3}/bin/python3 - "$out" ${ordinary} ${candidate} ${pkgs.binutils}/bin/readelf <<'PY'
      import hashlib
      import json
      from pathlib import Path
      import re
      import subprocess
      import sys

      output, ordinary, candidate = map(Path, sys.argv[1:4])
      names = sorted(path.name for path in (ordinary / "bin").iterdir())
      if names != sorted(path.name for path in (candidate / "bin").iterdir()):
          raise ValueError("boot package installed artifact inventory changed")
      scripts = {}
      for name in names:
          if name == "aos-boot-identity":
              continue
          baseline, actual = ordinary / "bin" / name, candidate / "bin" / name
          if baseline.read_bytes() != actual.read_bytes() or baseline.stat().st_mode != actual.stat().st_mode:
              raise ValueError("boot helper script changed: " + name)
          scripts[name] = hashlib.sha256(actual.read_bytes()).hexdigest()

      def elf(package):
          binary = package / "bin/aos-boot-identity"
          dynamic = subprocess.check_output([sys.argv[4], "-d", str(binary)], text=True)
          headers = subprocess.check_output([sys.argv[4], "-l", str(binary)], text=True)
          return {
              "needed": sorted(re.findall(r"\(NEEDED\).*\[(.+)\]", dynamic)),
              "runpath": re.findall(r"\((?:RUNPATH|RPATH)\).*\[(.+)\]", dynamic),
              "interpreter": re.findall(r"Requesting program interpreter: (.+)\]", headers),
          }

      if elf(ordinary) != elf(candidate):
          raise ValueError("boot command runtime ELF contract changed")
      report = {
          "status": "PASS", "installed_names": names, "script_sha256": scripts,
          "elf": elf(candidate), "installed_cli_tests_passed_for_both_drivers": True,
          "native_and_bazel_test_inventory_identical": True,
      }
      (output / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
      PY
      printf 'PASS\n' > "$out/result"
    '';
  all = pkgs.runCommand "aos-bazel-boot-identity-production-checks" {buildDeps = [driver-selection parity];} ''
    mkdir -p "$out"
    cp ${parity}/report.json "$out/"
    cp ${parity}/test-parity.json "$out/"
    printf 'PASS\n' > "$out/result"
  '';
}
