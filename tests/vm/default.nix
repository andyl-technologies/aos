# tests/vm/default.nix — VM integration test suite (per-check-group derivations)
#
# Each check group gets its own VM test derivation, independently cacheable
# by Nix. Aggregate targets provide backwards-compatible groupings.
#
# Individual tests:
#   nix-build -A checks.vm.boot-basics
#   nix-build -A checks.vm.ssh
#   nix-build -A checks.vm.nginx
#
# Aggregate (backwards-compatible) targets:
#   nix-build -A checks.vm.boot              (alias for boot-basics)
#   nix-build -A checks.vm.services          (systemd-basics + chrony + ssh)
#   nix-build -A checks.vm.server-security   (kernel-security + ssh + firewall + ...)
#
# Validation (no VM, instant):
#   nix-build -A checks.vm.validate
{
  pkgs,
  lib,
  systems,
  testTools,
}: let
  harness = import ../../lib/testing {inherit pkgs lib testTools;};

  # ---------------------------------------------------------------------------
  # Declarative mapping: check group name -> system variant
  # ---------------------------------------------------------------------------
  moduleTests = {
    boot-basics = {
      variant = "base";
    };
    filesystem = {
      variant = "base";
    };
    kernel-security = {
      variant = "server";
    };
    networking-base = {
      variant = "server";
    };
    systemd-basics = {
      variant = "server";
    };
    ssh = {
      variant = "server";
    };
    firewall = {
      variant = "server";
    };
    hardening = {
      variant = "server";
    };
    selinux = {
      variant = "server";
    };
    audit = {
      variant = "server";
    };
    chrony = {
      variant = "server";
    };
    container-support = {
      variant = "k8s-worker";
    };
    containerd = {
      variant = "k8s-worker";
    };
    kubelet = {
      variant = "k8s-worker";
    };
    k8s-networking = {
      variant = "k8s-worker";
    };
    node-exporter = {
      variant = "k8s-worker";
    };
    k8s-control-plane = {
      variant = "k8s-control-plane";
    };
    nginx = {
      variant = "seed";
    };
    nix-daemon = {
      variant = "seed";
    };
    seed = {
      variant = "seed";
    };
  };

  # ---------------------------------------------------------------------------
  # Auto-generate per-check-group VM test derivations
  # ---------------------------------------------------------------------------
  perCheckTests =
    builtins.mapAttrs (
      name: spec: let
        checkModule = import ./checks/${name}.nix {
          inherit (harness) mkCheck mkCheckGroup;
        };
      in
        harness.mkVMTest {
          inherit name;
          system = systems.${spec.variant};
          checks = [checkModule];
        }
    )
    moduleTests;

  # ---------------------------------------------------------------------------
  # Aggregate helper: trivial derivation that depends on constituent tests
  # ---------------------------------------------------------------------------
  mkAggregate = name: testNames:
    pkgs.mkDerivation {
      pname = "aos-vm-aggregate-${name}";
      version = "0";
      src = null;
      buildDeps = builtins.map (n: perCheckTests.${n}) testNames;
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
    seed-all = mkAggregate "seed-all" [
      "nginx"
      "nix-daemon"
      "seed"
    ];
    kubernetes = mkAggregate "kubernetes" [
      "container-support"
      "containerd"
      "kubelet"
      "k8s-networking"
    ];
    k8s-services = mkAggregate "k8s-services" [
      "containerd"
      "kubelet"
      "k8s-networking"
      "node-exporter"
    ];
  };

  # ---------------------------------------------------------------------------
  # Collect all check modules for the validation gate
  # ---------------------------------------------------------------------------
  allChecks = let
    mkC = {
      inherit (harness) mkCheck mkCheckGroup;
    };
  in
    builtins.map (name: import ./checks/${name}.nix mkC) (builtins.attrNames moduleTests);
in
  # Merge: individual tests + aggregates/aliases + validate
  perCheckTests
  // aggregates
  // {
    # Pre-flight syntax validation (no VM, instant)
    validate = harness.validateChecks {
      inherit pkgs;
      checks = allChecks;
    };
  }
