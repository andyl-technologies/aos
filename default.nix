# default.nix — ANDYL OS
#
# The single entry point for everything AOS: library, packages, systems,
# modules, and checks. The flake wraps this for Nix flake consumers and
# adds dev-only things (devShell, formatter).
#
# Usage:
#   nix-build -A pkgs.coreutils                     Build a package
#   nix-build -A stdenv                              Build the production stdenv
#   nix-build -A systems.server.build.toplevel       Build the server system
#   nix-build -A systems.server.checks.boot-basics   Run a module check
#   nix-build -A systems.server.checks.system-boot   Run a system-level check
#   nix-build -A checks                              Run all tests
#   nix-build -A checks.eval                         Run evaluation checks only
#
# Architecture:
#   Check derivations are produced inside the module system via
#   modules/base/checks.nix, which transforms system.checks specs
#   into system.build.checks derivations. Each system variant
#   (server, edge) gets its own set of checks accessible as
#   systems.<name>.checks.<check-name>.
#
# Structure:
#   stdenv/  — Bootstrap chain + toolchain ladder + stdenv (self-contained)
#   pkgs/    — Package definitions
#   lib/     — Library functions (derivations, modules, types, etc.)
#   modules/ — NixOS-style configuration modules (including tests)
#   systems/ — Golden image definitions (auto-discovered)
{
  system ? builtins.currentSystem,
  crossSystem ? null,
}: let
  lib = import ./lib {
    inherit system;
    bash = stdenv.bash;
  };
  buildPlatform = lib.platform;
  hostPlatform =
    if crossSystem != null
    then lib.mkPlatform crossSystem
    else buildPlatform;

  # Self-contained stdenv: hex0 bootstrap → toolchain ladder → production stdenv.
  stdenv = import ./stdenv {
    inherit buildPlatform hostPlatform;
    targetPlatform = hostPlatform;
  };

  # All packages are built hermetically from source using only stdenv.
  pkgs = import ./pkgs {inherit lib stdenv;};

  # Auto-discovered module list.
  modules = import ./modules;

  # Build a system from a system definition module (or list of modules).
  #
  # Accepts three calling conventions:
  #   mkSystem ./path.nix                              — single module path
  #   mkSystem [ ./a.nix ./b.nix ]                     — list of modules
  #   mkSystem { modules = [...]; specialArgs = {}; }   — full attrset
  mkSystem = args: let
    moduleList =
      if builtins.isList args
      then args
      else if builtins.isAttrs args && args ? modules
      then args.modules
      else [args];
    specialArgs =
      if builtins.isAttrs args && args ? specialArgs
      then args.specialArgs
      else {};
  in
    lib.evalModules {
      modules = modules ++ moduleList;
      inherit pkgs lib specialArgs;
    };

  # Auto-discover system definitions from ./systems/*.nix
  discoverSystems = let
    entries = builtins.readDir ./systems;
    nixFiles = builtins.filter (
      name:
        entries.${name}
        == "regular"
        && builtins.match ".*\\.nix" name != null
        && builtins.substring 0 1 name != "_"
    ) (builtins.attrNames entries);
  in
    builtins.listToAttrs (
      map (name: {
        name = lib.removeSuffix ".nix" name;
        value = let
          evaluated = mkSystem (./systems + "/${name}");
        in {
          config = evaluated.config;
          options = evaluated.options;
          build = {
            toplevel = evaluated.config.system.build.toplevel;
            kernel = evaluated.config.system.build.kernel;
            initrd = evaluated.config.system.build.initrd;
            image = evaluated.config.system.build.image;
          };
          # VM test derivations — produced inside the module system by
          # modules/base/checks.nix, not by external collection scripts.
          checks = evaluated.config.system.build.checks;
        };
      })
      nixFiles
    );

  # ---------------------------------------------------------------------------
  # Test infrastructure
  # ---------------------------------------------------------------------------

  # The default system used for eval/build checks and package integration tests.
  serverSystem = mkSystem ./systems/server.nix;

  # Testing harness (headless mode for package integration tests)
  testing = import ./lib/testing {inherit pkgs lib;};

  prefixAttrs = prefix: attrs:
    builtins.listToAttrs (
      map (name: {
        name = "${prefix}-${name}";
        value = attrs.${name};
      }) (builtins.attrNames attrs)
    );

  # ---------------------------------------------------------------------------
  # APM/APR VM tests (headless Firecracker, registry + tracking + packages)
  # ---------------------------------------------------------------------------
  apmTests = import ./tests/vm/apm {inherit testing pkgs;};

  # ---------------------------------------------------------------------------
  # Package integration checks (Firecracker-based, defined on packages)
  # ---------------------------------------------------------------------------
  packageChecks = builtins.foldl' (
    acc: name: let
      pkg = pkgs.${name};
    in
      if builtins.isAttrs pkg && pkg ? checks && builtins.isFunction pkg.checks
      then
        acc
        // prefixAttrs name (
          pkg.checks {
            inherit testing pkgs;
            self = pkg;
          }
        )
      else acc
  ) {} (builtins.attrNames pkgs);

  # Stdenv cross-cutting integration check
  stdenvChecks = {
    cross-cutting-c-pipeline = testing.mkVMTest {
      name = "cross-cutting-c-pipeline";
      rootfsDeps = [pkgs.binutils];
      testScript = ''
        cat > /tmp/pipeline.c << 'EOF'
        #include <stdio.h>
        int add(int a, int b) { return a + b; }
        int main(void) {
            int result = add(3, 4);
            printf("3 + 4 = %d\n", result);
            if (result != 7) return 1;
            return 0;
        }
        EOF

        echo "==> Stage 1: Preprocessing (gcc -E)"
        gcc -E /tmp/pipeline.c -o /tmp/pipeline.i

        echo "==> Stage 2: Compile to assembly (gcc -S)"
        gcc -S /tmp/pipeline.i -o /tmp/pipeline.s

        echo "==> Stage 3: Assemble to object (gcc -c)"
        gcc -c /tmp/pipeline.s -o /tmp/pipeline.o

        echo "==> Stage 4: Link to binary"
        gcc /tmp/pipeline.o -o /tmp/pipeline

        echo "==> Stage 5: Run the binary"
        /tmp/pipeline
        echo "C compilation pipeline: PASS"
      '';
    };
  };

  # ---------------------------------------------------------------------------
  # Fleet tests (multi-VM, inherently span multiple systems)
  # ---------------------------------------------------------------------------
  fleetHarness = import ./lib/testing/fleet.nix {inherit pkgs lib;};

  discoverFleetTests = let
    fleetSpec = import ./lib/testing/fleet-spec.nix {inherit lib pkgs;};

    entries = builtins.readDir ./tests/fleet;
    fleetFiles = builtins.filter (
      n:
        entries.${n}
        == "regular"
        && builtins.match ".*\\.nix" n != null
        && builtins.substring 0 1 n != "_"
    ) (builtins.attrNames entries);

    loadSpec = filename: let
      raw = (import (./tests/fleet + "/${filename}")) {
        inherit lib pkgs;
        systems = discoverSystems;
      };
      eval = lib.evalModules {
        modules = [
          {options.spec = lib.mkOption {type = fleetSpec.fleetSpecType;};}
          {config.spec = raw;}
        ];
      };
    in
      eval.config.spec;
  in
    builtins.listToAttrs (
      builtins.map (filename: {
        name = lib.removeSuffix ".nix" filename;
        value = fleetHarness.mkFleetTest (loadSpec filename);
      })
      fleetFiles
    );
in {
  inherit lib pkgs stdenv modules mkSystem;

  # Auto-discovered golden image systems.
  # Each system has .config, .options, .build, and .checks.
  systems = discoverSystems;

  # Eval-only benchmark attrs (never built). `bench.wide` instantiates every
  # IFD-free package in one evaluation (see tests/bench/wide.nix);
  # `bench.compute.*` are self-contained compute workloads sized for
  # evaluator benchmarking (see tests/bench/compute.nix).
  bench =
    import ./tests/bench/wide.nix {inherit pkgs lib;}
    // {
      compute = import ./tests/bench/compute.nix {};
    };

  # Checks hierarchy — module checks come from systems, everything else
  # stays at the top level.
  checks = {
    eval = import ./lib/testing/eval.nix {
      inherit pkgs lib mkSystem;
      system = serverSystem;
    };
    build = let
      critical-pkgs = import ./tests/build/critical-pkgs.nix {inherit pkgs lib;};
      hardening-probe = import ./tests/build/hardening-probe.nix {inherit pkgs lib;};
      kernel-config = import ./tests/build/kernel-config.nix {inherit pkgs lib;};
    in {
      inherit critical-pkgs hardening-probe kernel-config;
      # Single target that pulls in the whole build-check group.
      all = pkgs.mkDerivation {
        pname = "aos-build-checks-all";
        version = "0";
        src = null;
        buildDeps =
          [critical-pkgs kernel-config]
          ++ builtins.attrValues hardening-probe;
        phases = [
          {
            name = "check";
            script = ''
              mkdir -p $out
              echo "PASS" > $out/result
            '';
          }
        ];
      };
    };
    tla = import ./lib/testing/tla.nix {inherit pkgs lib;};
    trivial-builders = import ./lib/testing/trivial-builders.nix {inherit pkgs lib;};
    module-args = import ./lib/testing/module-args.nix {inherit pkgs lib;};
    module-enforcement = import ./lib/testing/module-enforcement.nix {inherit pkgs lib;};
    ignition-format = import ./lib/testing/ignition-format.nix {inherit pkgs lib;};
    fleet-spec = import ./lib/testing/fleet-spec-check.nix {inherit pkgs lib;};
    systemd-lib = import ./lib/testing/systemd-lib.nix {inherit pkgs lib;};
    systemd-generate = import ./lib/testing/systemd-generate.nix {inherit pkgs lib;};
    # Module-level VM checks (from server system, for backwards compat)
    vm =
      serverSystem.config.system.build.checks
      // {
        apm = apmTests;
      };
    integration = packageChecks // stdenvChecks;
    fleet = discoverFleetTests;
  };
}
