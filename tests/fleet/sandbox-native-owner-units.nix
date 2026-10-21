# Executes the remaining native-profile owners in an installed AOS guest.
{
  lib,
  mkSystem,
  pkgs,
  ...
}: let
  owners = [
    "aos-sandbox-broker"
    "aos-sandbox-guest-root-realization"
    "aos-sandbox-host"
    "aos-sandbox-linux"
    "aos-sandbox-network"
  ];
  packageFlags = lib.concatMapStrings (owner: " -p ${owner}") owners;
  # Select the kernel before adding the fixture that consumes its build DATA.
  kernelSystem = mkSystem [../../systems/server-test.nix];
  kernel = kernelSystem.config.system.build.kernel;

  # Retain the exact selected kernel's associated DATA, without installing its
  # entire development tree. Both compilation and guest tests read these bytes.
  layout = pkgs.runCommand "sandbox-native-unit-kernel-layout" {} ''
    mkdir -p "$out"
    cp -r ${kernel.dev}/share/aos-kernel-clone-layout-v1/. "$out/"
  '';
  tests = pkgs.mkCargoPackage {
    pname = "aos-sandbox-native-owner-unit-tests";
    version = "0.1.0";
    src = import ../../pkgs/tools/aos/_workspace-source.nix {inherit lib;};
    cargoDeps = pkgs.aos.passthru.cargoDeps;
    cargoRoot = "crates";
    buildType = "debug";
    cargoBuildCommands = [
      "test --no-run --lib --frozen --offline -j$NIX_BUILD_CORES${packageFlags} --features aos-sandbox-linux/selected-kernel-clone-layout"
    ];
    doCheck = false;
    installBins = false;
    buildDeps = [pkgs.protobuf];
    runtimeDeps = [];
    cargoEnv = {
      PROTOC = "${pkgs.protobuf}/bin/protoc";
      AOS_KERNEL_CLONE_LAYOUT_DIR = "${layout}";
    };
    # Keep synthetic input hashes distinct while scrubbing real build refs.
    nukeRefsKeep = map (hash: "/nix/store/" + hash + "-unit-fixture") [
      "00000000000000000000000000000000"
      "11111111111111111111111111111111"
      "22222222222222222222222222222222"
      "33333333333333333333333333333333"
      "44444444444444444444444444444444"
      "55555555555555555555555555555555"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
      "0123456789abcdfghijklmnpqrsvwxyz"
    ];

    postBuild = ''
      mkdir -p native-tests
      artifact_dir="''${CARGO_TARGET_DIR:-target}/debug/deps"
      ${lib.concatMapStringsSep "\n" (owner: let
          prefix = builtins.replaceStrings ["-"] ["_"] owner;
        in ''
          count=0
          for candidate in "$artifact_dir"/${prefix}-*; do
            if [ -f "$candidate" ] && [ -x "$candidate" ]; then
              install -m 0755 "$candidate" native-tests/${owner}
              count=$((count + 1))
            fi
          done
          if [ "$count" -ne 1 ]; then
            echo "expected one ${owner} libtest executable, found $count" >&2
            exit 1
          fi
        '')
        owners}
    '';
    postInstall = ''
      mkdir -p "$out/bin"
      install -m 0755 native-tests/* "$out/bin/"
    '';
  };
  system = mkSystem [
    ../../systems/server-test.nix
    {
      environment.systemPackages = [tests pkgs.util-linux];
      system.build.kernel = lib.mkForce kernel;
    }
  ];
in {
  name = "sandbox-native-owner-units";
  timeout = 1200;
  bootTimeout = 240;
  machines.vm = {inherit system;};

  testScript = ''
    import re
    import tomllib

    # Require every exact case moved out of the build sandbox by its existing
    # native profile. A successful empty or conditionally reduced suite cannot
    # stand in for these named tests.
    with open("${../../crates/.config/nextest.toml}", "rb") as stream:
        expression = tomllib.load(stream)["profile"]["nix-sandbox"]["default-filter"]
    native_groups = dict(re.findall(
        r"\(package\(=([^)]+)\) & \((.*?)\)\)", expression, re.S,
    ))

    vm.wait_for_unit("multi-user.target", timeout=180)
    vm.succeed("install -d -m 0700 -o 1000 -g 1000 /var/lib/aos-sandbox-native-unit-tests")
    for owner in ${builtins.toJSON owners}:
        binary = f"/var/lib/aos-sandbox-native-unit-tests/{owner}"
        vm.succeed(f"install -m 0755 ${tests}/bin/{owner} {binary}")
        output = vm.succeed(
            "cd /var/lib/aos-sandbox-native-unit-tests && "
            "RUST_MIN_STACK=33554432 AOS_KERNEL_CLONE_LAYOUT_DIR=${layout} "
            "${pkgs.util-linux}/bin/setpriv --reuid=1000 --regid=1000 --clear-groups "
            f"{binary} --test-threads=1",
            timeout=600,
        )
        assert "test result: ok." in output, (owner, output)
        assert "0 filtered out" in output, (owner, output)
        native_cases = re.findall(r"test\(=([^)]+)\)", native_groups[owner])
        assert native_cases, owner
        for name in native_cases:
            assert f"test {name} ... ok" in output, (owner, name, output)
        summaries = [line for line in output.splitlines() if line.startswith("test result:")]
        summary = summaries[-1]
        print(f"{owner}: {summary}; {len(native_cases)} required native cases")
  '';
}
