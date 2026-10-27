##! Exercises native source-location mapping with the actual AOS compiler.
{
  system ? builtins.currentSystem,
  pkgs ? (import ../../.. {inherit system;}).pkgs,
}: let
  compiler = import ../../../pkgs/build-support/_bazel/native-source-paths.nix {inherit pkgs;};
in rec {
  inherit compiler;
  toolchains = pkgs.mkAosBazelToolchains {
    cc = compiler;
    identity = "native-source-paths";
  };
  cli = import ../../../tests/build/_bazel-aos-cli-production.nix {
    inherit pkgs toolchains;
    sourceInventory = ../metadata/aos-cli-inventory.json;
  };
  cli-repeat = pkgs.mkAosBazelBuild {
    pname = "aos-bazel-aos-cli-native-source-paths-repeat";
    workspace = cli.workspace;
    targets = ["//crates/cli/aos-cli:production_binaries" "//crates/cli/aos-cli:production_suite_license_closure"];
    retainActionGraph = true;
  };
  cli-repeat-installed = pkgs.mkAosBazelPackage {
    pname = "aos-cli";
    version = "0.1.0";
    build = cli-repeat;
    packageLabel = "//crates/cli/aos-cli:production_binaries";
    runtimeDeps = [pkgs.gcc-libs pkgs.openssl pkgs.sqlite pkgs.libssh2 pkgs.zlib];
  };
  cli-repeatability = import ../../../tests/build/_bazel-native-cli-repeatability.nix {
    inherit pkgs;
    first = cli.build;
    second = cli-repeat;
    installed = cli.installed;
    repeated = cli-repeat-installed;
    runtime = cli.runtime-smoke;
  };
  check =
    pkgs.runCommand "aos-bazel-native-source-paths-check" {
      buildDeps = [pkgs.python3];
      sharedBuildCache = false;
    } ''
      mkdir -p "$out"
      PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 - \
        ${compiler}/bin/cc ${pkgs.cc}/bin/cc "$out" <<'PYTHON'
      import hashlib
      import json
      import os
      from pathlib import Path
      import subprocess
      import sys

      mapped_compiler, ordinary_compiler = sys.argv[1:3]
      output = Path(sys.argv[3])
      scratch = Path.cwd()
      source_repository = scratch / "source-repository"
      source_repository.mkdir()
      source_text = """#include <stdio.h>
      #include "location.h"
      int main(void) {
          puts(__FILE__);
          puts(__BASE_FILE__);
          puts(header_location());
          return 0;
      }
      """
      header_text = 'static const char *header_location(void) { return __FILE__; }\n'

      def run(arguments, directory, environment):
          return subprocess.run(arguments, cwd=directory, env=environment,
                                capture_output=True, text=True, timeout=30)

      def compile_program(compiler, root, directory, arguments, environment, destination):
          result = run([compiler, "-g", "-O2", *arguments, "-o", str(destination)],
                       directory, environment)
          assert result.returncode == 0, result.stderr
          executed = run([str(destination)], scratch, environment)
          assert executed.returncode == 0, executed.stderr
          return {
              "sha256": hashlib.sha256(destination.read_bytes()).hexdigest(),
              "locations": executed.stdout.splitlines(),
          }

      cases = {}
      for mode in ["working-directory", "absolute-arguments", "output-directory"]:
          samples = []
          for number in [17, 963]:
              root = scratch / mode / "sandbox/linux-sandbox" / str(number) / "execroot/_main"
              generated = root / "generated"
              generated.mkdir(parents=True)
              source = generated / "native.c"
              source.write_text(source_text)
              (generated / "location.h").write_text(header_text)
              environment = dict(os.environ)
              environment.pop("OUT_DIR", None)
              if mode == "working-directory":
                  directory, arguments = root, ["generated/native.c"]
              elif mode == "absolute-arguments":
                  # A source-repository working directory need not be under the
                  # action root when a generator passes absolute output paths.
                  directory, arguments = source_repository, [str(source)]
              else:
                  # A response file can hide all paths from the compiler argv.
                  # Build-script OUT_DIR still identifies the private action root.
                  response = source_repository / "compiler.rsp"
                  response.write_text(str(source) + "\n")
                  directory, arguments = source_repository, ["@compiler.rsp"]
                  environment["OUT_DIR"] = str(generated)

              ordinary = compile_program(ordinary_compiler, root, directory, arguments,
                                         environment, generated / "ordinary")
              mapped = compile_program(mapped_compiler, root, directory, arguments,
                                       environment, generated / "mapped")
              expected_source = "generated/native.c" if mode == "working-directory" else "./generated/native.c"
              expected_header = "generated/location.h" if mode == "working-directory" else "./generated/location.h"
              assert mapped["locations"] == [expected_source, expected_source, expected_header], mapped
              samples.append({"ordinary": ordinary, "mapped": mapped})

          assert samples[0]["ordinary"]["sha256"] != samples[1]["ordinary"]["sha256"], mode
          assert samples[0]["mapped"] == samples[1]["mapped"], mode
          cases[mode] = samples

      plain = source_repository / "native.c"
      plain.write_text(source_text)
      (source_repository / "location.h").write_text(header_text)
      ordinary = compile_program(ordinary_compiler, None, source_repository, [str(plain)],
                                 dict(os.environ), source_repository / "ordinary")
      mapped = compile_program(mapped_compiler, None, source_repository, [str(plain)],
                               dict(os.environ), source_repository / "mapped")
      assert ordinary == mapped
      cases["ordinary-directory-passthrough"] = mapped

      root = scratch / "absolute-arguments/sandbox/linux-sandbox/17/execroot/_main"
      override = compile_program(mapped_compiler, root, source_repository,
                                 [f"-ffile-prefix-map={root}=caller-selected", str(root / "generated/native.c")],
                                 dict(os.environ), source_repository / "override")
      assert override["locations"] == ["caller-selected/generated/native.c"] * 2 + ["caller-selected/generated/location.h"]
      cases["caller-mapping-precedence"] = override

      invalid = source_repository / "invalid.c"
      invalid.write_text("invalid C source\n")
      failures = [run([compiler, "-c", str(invalid)], source_repository, dict(os.environ))
                  for compiler in [ordinary_compiler, mapped_compiler]]
      assert failures[0].returncode != 0 and failures[0].returncode == failures[1].returncode
      cases["compiler-failure-exit-status"] = failures[0].returncode
      (output / "evidence.json").write_text(json.dumps({
          "schema_version": 1, "status": "PASS", "cases": cases,
          "limits": ["Uses real source-built native compilation in a Nix sandbox; actual Bazel build-script and production repeatability qualification remain separate."],
      }, indent=2, sort_keys=True) + "\n")
      PYTHON
    '';
}
