##! gRPC's pinned protoc-gen-validate repository from audited source.
{
  mkDerivation,
  fetchgit,
  buildPackages,
  bazelOfflineModules,
}: let
  revision = "4694024279bdac52b77e22dc87808bd0fd732b69";
  moduleSource = import ./_bazel-module-source.nix {inherit fetchgit buildPackages;};
  source = moduleSource {
    name = "protoc-gen-validate";
    version = builtins.substring 0 12 revision;
    url = "https://github.com/envoyproxy/protoc-gen-validate.git";
    rev = revision;
    hash = "sha256-ouo6raNbvQyuY4IY1JEN45Ss7zb3EoR/WIRzL7hXLNI=";
    fetchCommit = true;
  };
in
  mkDerivation {
    pname = "bazel-protoc-gen-validate-source";
    version = builtins.substring 0 12 revision;
    src = source;

    buildDeps = [buildPackages.patch buildPackages.python3];
    runtimeDeps = [];

    phases = [
      {
        name = "prepare";
        script = ''
          mkdir source
          cp -R "$src"/. source/
          chmod -R u+w source
          (cd source && patch -p1 < ${bazelOfflineModules.grpc}/third_party/protoc-gen-validate.patch)
        '';
      }
      {
        name = "audit-source";
        script = ''
          python3 - <<'PY'
          from pathlib import Path

          root = Path("source")
          compiled_suffixes = {
              ".class", ".jar", ".so", ".dylib", ".dll", ".a", ".o",
              ".wasm", ".exe", ".bin", ".zip", ".tar", ".gz", ".xz",
          }
          files = [path for path in root.rglob("*") if path.is_file()]
          if len(files) != 237:
              raise SystemExit(f"Expected 237 protoc-gen-validate sources, found {len(files)}")
          for path in files:
              if path.suffix.lower() in compiled_suffixes:
                  raise SystemExit(f"Compiled protoc-gen-validate input: {path}")
              path.read_text(encoding="utf-8")
          PY
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out"
          cp -R source/. "$out/"
        '';
      }
    ];
  }
