# tests/vm/default.nix — VM integration test suite (per-check-group derivations)
#
# Checks are defined in modules via `system.checks.<name>` and automatically
# discovered from evaluated system configs. Each check group gets its own VM
# test derivation, independently cacheable by Nix.
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
  #
  # Modules define checks via system.checks.<name>. This mapping tells the
  # harness which system variant to use for each check group. The check
  # definitions themselves come from the evaluated module config.
  # ---------------------------------------------------------------------------
  checkVariants = {
    boot-basics = "base";
    filesystem = "base";
    kernel-security = "server";
    networking-base = "server";
    systemd-basics = "server";
    ssh = "server";
    firewall = "server";
    hardening = "server";
    selinux = "server";
    audit = "server";
    chrony = "server";
    container-support = "k8s-worker";
    containerd = "k8s-worker";
    kubelet = "k8s-worker";
    k8s-networking = "k8s-worker";
    node-exporter = "k8s-worker";
    k8s-control-plane = "k8s-control-plane";
    nginx = "seed";
    nix-daemon = "seed";
    seed = "seed";
  };

  # ---------------------------------------------------------------------------
  # Auto-generate per-check-group VM test derivations from module-defined checks
  # ---------------------------------------------------------------------------
  perCheckTests =
    builtins.mapAttrs (
      name: variantName: let
        system = systems.${variantName};
        checkGroup = system.config.system.checks.${name};
      in
        harness.mkVMTest {
          inherit name;
          inherit system;
          checks = [checkGroup];
        }
    )
    checkVariants;

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
  # Collect all check groups for the validation gate
  # ---------------------------------------------------------------------------
  allChecks =
    builtins.map (
      name: let
        variantName = checkVariants.${name};
        system = systems.${variantName};
      in
        system.config.system.checks.${name}
    ) (builtins.attrNames checkVariants);
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
