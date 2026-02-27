# lib/testing/collect.nix — Collect all checks from the module system and packages
#
# Central test collection function that replaces the former tests/ directory.
# All test definitions live alongside their code (in modules or packages);
# this file only discovers and wraps them into derivations.
#
# Sources:
#   - VM checks:        system.config.system.checks.<name>   (module-defined)
#   - Cloud-init tests: system.config.system.cloudInitTests.* (cloud-init module)
#   - Fleet tests:      system.config.system.fleetTests.*     (module-defined)
#   - Integration:      pkg.checks { testing, self, pkgs }    (per-package)
#   - Eval/Build:       lib/testing/eval.nix, lib/testing/build.nix
#
# Usage:
#   allChecks = import ./lib/testing/collect.nix { inherit pkgs lib testTools; system = aosSystem; };
{
  pkgs,
  lib,
  testTools,
  system,
}:
let
  # VM test harness (needs QEMU etc. for system-mode tests)
  harness = import ./. { inherit pkgs lib testTools; };

  # Integration test harness (headless Firecracker, no QEMU needed)
  testing = import ./. {
    inherit pkgs lib;
    testTools = { };
  };

  prefixAttrs =
    prefix: attrs:
    builtins.listToAttrs (
      builtins.map (name: {
        name = "${prefix}-${name}";
        value = attrs.${name};
      }) (builtins.attrNames attrs)
    );

  # ---------------------------------------------------------------------------
  # VM checks: auto-discover from system.config.system.checks
  # ---------------------------------------------------------------------------
  moduleCheckNames = builtins.attrNames system.config.system.checks;

  perCheckTests = builtins.listToAttrs (
    builtins.map (name: {
      inherit name;
      value = harness.mkVMTest {
        inherit name system;
        checks = [ system.config.system.checks.${name} ];
      };
    }) moduleCheckNames
  );

  # ---------------------------------------------------------------------------
  # Cloud-init tests: auto-discover from system.config.system.cloudInitTests
  # ---------------------------------------------------------------------------
  ciTests = builtins.mapAttrs (
    name: spec:
    harness.mkVMTest {
      inherit name system;
      checks = [ spec.checks ];
      userdata = spec.userdata;
    }
  ) system.config.system.cloudInitTests;

  # ---------------------------------------------------------------------------
  # Aggregate helper: trivial derivation that depends on constituent tests
  # ---------------------------------------------------------------------------
  allVMTests = perCheckTests // ciTests;

  mkAggregate =
    name: testNames:
    pkgs.mkDerivation {
      pname = "aos-vm-aggregate-${name}";
      version = "0";
      src = null;
      buildDeps = builtins.map (n: allVMTests.${n}) testNames;
      phases = [
        {
          name = "aggregate";
          script = ''
            mkdir -p $out
            echo "All tests passed: ${builtins.concatStringsSep ", " testNames}" > $out/result
          '';
        }
      ];
    };

  # ---------------------------------------------------------------------------
  # Backwards-compatible aggregate / alias targets
  # ---------------------------------------------------------------------------
  aggregates = {
    # Simple aliases (single check group -> old name)
    boot = perCheckTests.boot-basics;
    immutability = perCheckTests.filesystem;
    security = perCheckTests.kernel-security;
    networking = perCheckTests.networking-base;

    # Multi-check aggregates
    services = mkAggregate "services" [
      "systemd-basics"
      "chrony"
      "ssh"
    ];
    server-security = mkAggregate "server-security" [
      "kernel-security"
      "ssh"
      "firewall"
      "hardening"
      "selinux"
      "audit"
    ];

    # Cloud-init aggregate targets
    cloud-init = mkAggregate "cloud-init" (builtins.attrNames ciTests);
    cloud-init-roles = mkAggregate "cloud-init-roles" [
      "ci-defaults"
      "ci-server-role"
      "ci-worker-role"
      "ci-control-plane-role"
    ];
    cloud-init-security = mkAggregate "cloud-init-security" [
      "ci-firewall-server"
      "ci-firewall-k8s-worker"
      "ci-firewall-k8s-cp"
      "ci-security"
    ];
  };

  # ---------------------------------------------------------------------------
  # Validation gate: check all check group scripts for syntax errors (no VM)
  # ---------------------------------------------------------------------------
  allCheckGroups =
    builtins.map (name: system.config.system.checks.${name}) moduleCheckNames
    ++ builtins.map (name: system.config.system.cloudInitTests.${name}.checks) (
      builtins.attrNames system.config.system.cloudInitTests
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

  # ---------------------------------------------------------------------------
  # Stdenv integration check: c-pipeline
  #
  # Tests the full gcc/binutils compilation pipeline (preprocess, compile to
  # assembly, assemble, link, run). Cannot be attributed to a single package
  # since binutils is part of stdenv, not a standalone package file.
  # ---------------------------------------------------------------------------
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
        echo "    Preprocessed output: $(wc -l < /tmp/pipeline.i) lines"

        echo "==> Stage 2: Compile to assembly (gcc -S)"
        gcc -S /tmp/pipeline.i -o /tmp/pipeline.s
        echo "    Assembly output: $(wc -l < /tmp/pipeline.s) lines"

        echo "==> Stage 3: Assemble to object (gcc -c)"
        gcc -c /tmp/pipeline.s -o /tmp/pipeline.o
        echo "    Object file: $(ls -l /tmp/pipeline.o | cut -d' ' -f5) bytes"

        echo "==> Stage 4: Link to binary"
        gcc /tmp/pipeline.o -o /tmp/pipeline

        echo "==> Stage 5: Run the binary"
        /tmp/pipeline
        echo "C compilation pipeline: PASS"
      '';
    };
  };

  # ---------------------------------------------------------------------------
  # Fleet tests: collected from system.config.system.fleetTests
  #
  # Fleet test specs use variant name strings rather than evaluated system
  # objects, so they cannot be wrapped with mkFleetTest yet. Collected here
  # for future use when the fleet test harness supports variant resolution.
  # ---------------------------------------------------------------------------
  fleetSpecs = system.config.system.fleetTests;
in
{
  eval = import ./eval.nix { inherit pkgs lib system; };
  build = import ./build.nix { inherit pkgs lib; };
  vm =
    allVMTests
    // aggregates
    // {
      validate = harness.validateChecks {
        inherit pkgs;
        checks = allCheckGroups;
      };
    };
  integration = packageChecks // stdenvChecks;
}
