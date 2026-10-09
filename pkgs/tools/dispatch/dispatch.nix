##! Portable assignment libraries, solver sessions, and supervised workers.
{
  lib,
  mkAosCargoPackage,
  aosWorkspaceVendor,
  bash,
  dispatch-rebalancer,
  withTests ? false,
}: let
  version = "0.1.0";
  packages = "-p dispatch -p dispatch-model -p dispatch-protocol -p dispatch-runtime -p dispatch-conformance";
  guide = builtins.toFile "dispatch-user-guide.md" (builtins.readFile ../../../docs/users/dispatch.md);
  buildCommands =
    [
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p dispatch -p dispatch-runtime --bins --features dispatch-runtime/systemd"
    ]
    ++ lib.optionals withTests [
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p dispatch-conformance --bin dispatch-systemd-probe"
    ];
  package = mkAosCargoPackage {
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
      ];
      target = [];
      role = "public-package";
    };
    pname =
      if withTests
      then "dispatch-tests"
      else "dispatch";
    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "A complete assignment problem with exact decimal quantities.";
        operation = "Validate the public JSON model through the packaged command.";
        expected = "The command accepts the model and returns its semantic commitment.";
        files."problem.json" = builtins.readFile ../../../crates/dispatch/examples/fixtures/packing.problem.json;
        artifacts = [];
        steps = [
          {
            argv = ["@out@/bin/dispatch" "validate" "--problem" "problem.json"];
            exit_code = 0;
            stderr.exact = "";
          }
        ];
      };
      badInput = {
        input = "A JSON object containing a duplicate semantic field.";
        operation = "Validate the malformed document before starting a solver.";
        expected = "The command rejects the duplicate field.";
        files."invalid.json" = ''{"model_version":"1","model_version":"1"}'';
        artifacts = [];
        steps = [
          {
            argv = ["@out@/bin/dispatch" "validate" "--problem" "invalid.json"];
            exit_code = 2;
            observes_rejection = true;
            stdout.exact = "";
          }
        ];
      };
    };
    version = "=${version}";
    cargoDeps = aosWorkspaceVendor;
    cargoRoot = "crates";
    cargoBuildCommands = buildCommands;
    cargoTestFlags = "${packages} --features dispatch-runtime/systemd";
    cargoEnv = {
      DISPATCH_TEST_REBALANCER = "${dispatch-rebalancer}/bin/dispatch-rebalancer";
    };
    doCheck = withTests;
    buildDeps = [];
    runtimeDeps = [bash dispatch-rebalancer];
    postBuild = lib.optionalString withTests ''
      if [ -z "''${AOS_CROSS_COMPILING:-}" ]; then
        cargo test --release --frozen --offline -j"$NIX_BUILD_CORES" \
          -p dispatch-conformance --features dispatch-runtime/systemd -- --ignored
      fi
    '';
    postInstall = ''
      mv "$out/bin/dispatch" "$out/bin/.dispatch-unwrapped"
      cat > "$out/bin/dispatch" <<EOF
      #!${bash}/bin/bash
      export DISPATCH_WORKER="\''${DISPATCH_WORKER:-$out/bin/dispatch-worker}"
      export DISPATCH_BACKEND="\''${DISPATCH_BACKEND:-${dispatch-rebalancer}/bin/dispatch-rebalancer}"
      exec "$out/bin/.dispatch-unwrapped" "\$@"
      EOF
      chmod +x "$out/bin/dispatch"
      ln -s ${dispatch-rebalancer}/bin/dispatch-rebalancer "$out/bin/dispatch-rebalancer"
      mkdir -p "$out/share/dispatch"
      cp -R dispatch/examples "$out/share/dispatch/examples"
      cp -R ../protocol/dispatch "$out/share/dispatch/protocol"
      cp ${guide} "$out/share/dispatch/dispatch.md"
    '';
    passthru = lib.optionalAttrs (!withTests) {
      tests = import ./dispatch.nix {
        inherit lib mkAosCargoPackage aosWorkspaceVendor bash dispatch-rebalancer;
        withTests = true;
      };
    };
    meta = {
      description = "Portable resource assignment and scoped native solver execution";
      license = "Apache-2.0";
      mainProgram = "dispatch";
    };
  };
in
  package
