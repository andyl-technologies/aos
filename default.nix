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
}:
let
  lib = import ./lib { inherit system; };
  buildPlatform = lib.platform;
  hostPlatform = if crossSystem != null then lib.mkPlatform crossSystem else buildPlatform;

  # Self-contained stdenv: hex0 bootstrap → toolchain ladder → production stdenv.
  stdenv = import ./stdenv {
    inherit buildPlatform hostPlatform;
    targetPlatform = hostPlatform;
  };

  # All packages are built hermetically from source using only stdenv.
  pkgs = import ./pkgs { inherit lib stdenv; };

  # Auto-discovered module list.
  modules = import ./modules;

  # Build a system from a system definition module (or list of modules).
  #
  # Accepts three calling conventions:
  #   mkSystem ./path.nix                              — single module path
  #   mkSystem [ ./a.nix ./b.nix ]                     — list of modules
  #   mkSystem { modules = [...]; specialArgs = {}; }   — full attrset
  mkSystem =
    args:
    let
      moduleList =
        if builtins.isList args then
          args
        else if builtins.isAttrs args && args ? modules then
          args.modules
        else
          [ args ];
      specialArgs =
        if builtins.isAttrs args && args ? specialArgs then args.specialArgs else { };
    in
    lib.evalModules {
      modules = modules ++ moduleList;
      inherit pkgs lib specialArgs;
    };

  # Auto-discover system definitions from ./systems/*.nix
  discoverSystems =
    let
      entries = builtins.readDir ./systems;
      nixFiles = builtins.filter (
        name:
        entries.${name} == "regular"
        && builtins.match ".*\\.nix" name != null
        && builtins.substring 0 1 name != "_"
      ) (builtins.attrNames entries);
    in
    builtins.listToAttrs (
      builtins.map (name: {
        name = lib.removeSuffix ".nix" name;
        value =
          let
            evaluated = mkSystem (./systems + "/${name}");
          in
          {
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
      }) nixFiles
    );

  # ---------------------------------------------------------------------------
  # Test infrastructure
  # ---------------------------------------------------------------------------

  testTools = {
    qemu = pkgs.qemu;
    socat = pkgs.socat;
    jq = pkgs.jq;
  };

  # The default system used for eval/build checks and package integration tests.
  serverSystem = mkSystem ./systems/server.nix;

  # Testing harness (headless mode for package integration tests)
  testing = import ./lib/testing {
    inherit pkgs lib;
    testTools = { };
  };

  # Testing harness (full mode for fleet tests and validation)
  harness = import ./lib/testing { inherit pkgs lib testTools; };

  prefixAttrs =
    prefix: attrs:
    builtins.listToAttrs (
      builtins.map (name: {
        name = "${prefix}-${name}";
        value = attrs.${name};
      }) (builtins.attrNames attrs)
    );

  # ---------------------------------------------------------------------------
  # Package integration checks (Firecracker-based, defined on packages)
  # ---------------------------------------------------------------------------
  packageChecks = builtins.foldl' (
    acc: name:
    let
      pkg = pkgs.${name};
    in
    if builtins.isAttrs pkg && pkg ? checks && builtins.isFunction pkg.checks then
      acc
      // prefixAttrs name (
        pkg.checks {
          inherit testing pkgs;
          self = pkg;
        }
      )
    else
      acc
  ) { } (builtins.attrNames pkgs);

  # Stdenv cross-cutting integration check
  stdenvChecks = {
    cross-cutting-c-pipeline = testing.mkVMTest {
      name = "cross-cutting-c-pipeline";
      rootfsDeps = [ pkgs.binutils ];
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
  fleetHarness = import ./lib/testing/fleet.nix { inherit pkgs lib testTools; };

  discoverFleetTests =
    let
      entries = builtins.readDir ./systems/tests;
      fleetFiles = builtins.filter (
        name:
        entries.${name} == "regular"
        && builtins.match ".*\\.nix" name != null
        && name != "default.nix"
        && builtins.substring 0 1 name != "_"
      ) (builtins.attrNames entries);

      specs = builtins.map (name: import (./systems/tests + "/${name}") { inherit lib; }) fleetFiles;
      fleetSpecs = builtins.filter (spec: (spec.type or "vm") == "fleet") specs;
    in
    builtins.listToAttrs (
      builtins.map (spec: {
        name = spec.name;
        value = fleetHarness.mkFleetTest {
          name = spec.name;
          machines = builtins.mapAttrs (
            mname: mspec:
            {
              system = mkSystem (./systems + "/${mspec.system}.nix");
              role = mspec.role or mname;
            }
          ) spec.machines;
          testScript = spec.testScript;
          timeout = spec.timeout or 300;
        };
      }) fleetSpecs
    );
in
{
  inherit lib pkgs stdenv modules mkSystem;

  # Auto-discovered golden image systems.
  # Each system has .config, .options, .build, and .checks.
  systems = discoverSystems;

  # Checks hierarchy — module checks come from systems, everything else
  # stays at the top level.
  checks = {
    eval = import ./lib/testing/eval.nix {
      inherit pkgs lib;
      system = serverSystem;
    };
    build = import ./lib/testing/build.nix { inherit pkgs lib; };
    tla = import ./lib/testing/tla.nix { inherit pkgs lib; };
    # Module-level VM checks (from server system, for backwards compat)
    vm = serverSystem.config.system.build.checks;
    integration = packageChecks // stdenvChecks;
  };

  # Fleet tests (multi-VM, span multiple systems)
  fleetTests = discoverFleetTests;

  # Backwards compatibility: systemChecks as a flat namespace
  # Maps "server-boot-basics" -> systems.server.checks.boot-basics, etc.
  systemChecks =
    let
      allSystems = discoverSystems;
      sysNames = builtins.attrNames allSystems;
    in
    builtins.foldl' (
      acc: sysName:
      acc // prefixAttrs sysName allSystems.${sysName}.checks
    ) { } sysNames
    // discoverFleetTests;
}
