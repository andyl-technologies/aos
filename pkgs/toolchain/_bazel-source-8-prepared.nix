##! Bazel 8 source tree with source-built JaCoCo release inputs.
{
  mkDerivation,
  bazelSource8,
  bazelJacoco,
  buildPackages,
}: let
  version = "8.6.0";
in
  mkDerivation {
    pname = "bazel-source-prepared";
    inherit version;
    src = bazelSource8;

    buildDeps = [buildPackages.python3];
    runtimeDeps = [];

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out"
          cp -a "$src"/. "$out"/
          chmod -R u+w "$out"

          destination="$out/third_party/java/jacoco"
          for archive in ${bazelJacoco}/share/java/*.jar; do
            cp "$archive" "$destination/"
          done

          # AOS targets Linux and Darwin. The Windows-only JNI classifier has
          # no source-built AOS toolchain and is unused by those platforms.
          python3 - "$out" <<'PY'
          import json
          from pathlib import Path
          import sys

          root = Path(sys.argv[1])
          module = root / "MODULE.bazel"
          declaration = '        "io.netty:netty-tcnative-boringssl-static:jar:windows-x86_64:2.0.56.Final",\n'
          module_text = module.read_text()
          if module_text.count(declaration) != 1:
              raise SystemExit("Unexpected Windows TCNative module declaration")
          module.write_text(module_text.replace(declaration, ""))

          third_party = root / "third_party/BUILD"
          windows_label = '"//src/conditions:windows": ["@maven//:io_netty_netty_tcnative_boringssl_static_windows_x86_64_file"],'
          third_party_text = third_party.read_text()
          if third_party_text.count(windows_label) != 1:
              raise SystemExit("Unexpected Windows TCNative Bazel label")
          third_party.write_text(third_party_text.replace(
              windows_label, '"//src/conditions:windows": [],',
          ))

          lock_path = root / "maven_install.json"
          lock = json.loads(lock_path.read_text())
          artifact = "io.netty:netty-tcnative-boringssl-static"
          classifier = f"{artifact}:jar:windows-x86_64"
          shasums = lock["artifacts"][artifact]["shasums"]
          if not shasums.pop("windows-x86_64", None):
              raise SystemExit("Missing Windows TCNative classifier checksum")

          dependencies = lock["dependencies"]
          if classifier not in dependencies:
              raise SystemExit("Missing Windows TCNative dependency entry")
          del dependencies[classifier]
          for entries in dependencies.values():
              if classifier in entries:
                  entries.remove(classifier)

          for packages in lock["packages"].values():
              if classifier in packages:
                  packages.remove(classifier)
          for repository_artifacts in lock["repositories"].values():
              if classifier in repository_artifacts:
                  repository_artifacts.remove(classifier)

          if lock["__INPUT_ARTIFACTS_HASH"] != -170859570:
              raise SystemExit("Unexpected Maven input signature")
          if lock["__RESOLVED_ARTIFACTS_HASH"] != 1513835236:
              raise SystemExit("Unexpected Maven resolved signature")
          # These are the source-built Starlark hashes of the edited inputs
          # and resolved artifact tree, using rules_jvm_external's algorithm.
          lock["__INPUT_ARTIFACTS_HASH"] = -30292075
          lock["__RESOLVED_ARTIFACTS_HASH"] = 2047592859

          lock_path.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n")
          PY
        '';
      }
    ];
  }
