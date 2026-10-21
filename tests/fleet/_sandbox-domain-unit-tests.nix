# Compiles the ordinary Domain libtest executable for an AOS guest. Native
# protected-ancestry cases run there, rather than inside the build sandbox.
{
  lib,
  pkgs,
}:
pkgs.mkCargoPackage {
  pname = "aos-sandbox-domain-unit-tests";
  version = "0.1.0";
  src = import ../../pkgs/tools/aos/_workspace-source.nix {inherit lib;};
  cargoDeps = pkgs.aos.passthru.cargoDeps;
  cargoRoot = "crates";
  buildType = "debug";
  cargoBuildCommands = [
    "test --no-run --lib --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-controller-domain"
  ];
  doCheck = false;
  installBins = false;
  # Preserve only the synthetic profile inputs. Cargo vendor references must
  # still be scrubbed; retaining them would violate the package closure policy.
  nukeRefsKeep = map (hash: "/nix/store/" + hash + "-unit-fixture") [
    "00000000000000000000000000000000"
    "11111111111111111111111111111111"
    "22222222222222222222222222222222"
    "33333333333333333333333333333333"
    "44444444444444444444444444444444"
    "55555555555555555555555555555555"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  ];
  buildDeps = [pkgs.protobuf];
  cargoEnv.PROTOC = "${pkgs.protobuf}/bin/protoc";
  runtimeDeps = [];

  postBuild = ''
    mkdir -p native-tests
    count=0
    artifact_dir="''${CARGO_TARGET_DIR:-target}/debug/deps"
    for candidate in "$artifact_dir"/aos_sandbox_controller_domain-*; do
      if [ -f "$candidate" ] && [ -x "$candidate" ]; then
        install -m 0755 "$candidate" native-tests/sandbox-domain-unit-tests
        count=$((count + 1))
      fi
    done
    if [ "$count" -ne 1 ]; then
      echo "expected exactly one Domain libtest executable, found $count" >&2
      exit 1
    fi
  '';
  postInstall = ''
    mkdir -p "$out/bin"
    install -m 0755 native-tests/sandbox-domain-unit-tests "$out/bin/"
  '';
}
