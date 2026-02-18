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
# Cloud-init tests (golden image, per-test userdata):
#   nix-build -A checks.vm.ci-defaults
#   nix-build -A checks.vm.ci-hostname
#   nix-build -A checks.vm.ci-server-role
#
# Aggregate targets:
#   nix-build -A checks.vm.boot              (alias for boot-basics)
#   nix-build -A checks.vm.services          (systemd-basics + chrony + ssh)
#   nix-build -A checks.vm.server-security   (kernel-security + ssh + firewall + ...)
#   nix-build -A checks.vm.cloud-init        (all cloud-init tests)
#   nix-build -A checks.vm.cloud-init-roles  (defaults + server + worker + cp)
#   nix-build -A checks.vm.cloud-init-security (firewall + security tests)
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
  # Cloud-init tests: golden image + per-test userdata
  #
  # Each test uses the same golden system variant but with different JSON
  # userdata injected into the rootfs at /var/lib/cloud/seed/nocloud/user-data.
  # This mirrors real-world behavior: one image, many configurations.
  # ---------------------------------------------------------------------------
  goldenSystem = systems.golden;

  ciCheckSpecs = {
    ci-defaults = {
      userdata = null;
      checks = import ./checks/ci-defaults.nix {inherit lib;};
    };
    ci-hostname = {
      userdata = builtins.toJSON {
        hostname = "test-webserver";
      };
      checks = import ./checks/ci-hostname.nix {inherit lib;};
    };
    ci-networking = {
      userdata = builtins.toJSON {
        hostname = "static-net-test";
        networking = {
          interfaces = {
            eth0 = {
              address = "10.0.0.5/24";
              gateway = "10.0.0.1";
              dns = "10.0.0.1";
            };
          };
        };
      };
      checks = import ./checks/ci-networking.nix {inherit lib;};
    };
    ci-users = {
      userdata = builtins.toJSON {
        users = [
          {
            name = "deploy";
            uid = 1000;
            groups = ["wheel"];
          }
        ];
      };
      checks = import ./checks/ci-users.nix {inherit lib;};
    };
    ci-ssh-keys = {
      userdata = builtins.toJSON {
        users = [
          {
            name = "deploy";
            uid = 1000;
            groups = ["wheel"];
            ssh_authorized_keys = [
              "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKeyForCloudInitVMTest deploy@test"
            ];
          }
        ];
      };
      checks = import ./checks/ci-ssh-keys.nix {inherit lib;};
    };
    ci-firewall-server = {
      userdata = builtins.toJSON {
        role = "server";
        firewall = {
          allowed_tcp = [22 80 443];
          allowed_udp = [];
          forward_policy = "drop";
        };
      };
      checks = import ./checks/ci-firewall-server.nix {inherit lib;};
    };
    ci-firewall-k8s-worker = {
      userdata = builtins.toJSON {
        role = "k8s-worker";
        firewall = {
          allowed_tcp = [22];
          allowed_udp = [];
          forward_policy = "accept";
        };
        kubernetes = {
          server_url = "https://10.0.0.10:6443";
          token_file = "/etc/rancher/k3s/agent-token";
        };
      };
      checks = import ./checks/ci-firewall-k8s-worker.nix {inherit lib;};
    };
    ci-firewall-k8s-cp = {
      userdata = builtins.toJSON {
        role = "k8s-control-plane";
        firewall = {
          allowed_tcp = [22];
          allowed_udp = [];
          forward_policy = "accept";
        };
        kubernetes = {
          cluster_init = true;
        };
      };
      checks = import ./checks/ci-firewall-k8s-cp.nix {inherit lib;};
    };
    ci-server-role = {
      userdata = builtins.toJSON {
        role = "server";
        hostname = "prod-web-01";
        firewall = {
          allowed_tcp = [22 80 443];
          allowed_udp = [];
          forward_policy = "drop";
        };
      };
      checks = import ./checks/ci-server-role.nix {inherit lib;};
    };
    ci-worker-role = {
      userdata = builtins.toJSON {
        role = "k8s-worker";
        hostname = "worker-01";
        firewall = {
          allowed_tcp = [22];
          allowed_udp = [];
          forward_policy = "accept";
        };
        kubernetes = {
          server_url = "https://10.0.0.10:6443";
          token_file = "/etc/rancher/k3s/agent-token";
        };
      };
      checks = import ./checks/ci-worker-role.nix {inherit lib;};
    };
    ci-control-plane-role = {
      userdata = builtins.toJSON {
        role = "k8s-control-plane";
        hostname = "cp-01";
        firewall = {
          allowed_tcp = [22];
          allowed_udp = [];
          forward_policy = "accept";
        };
        kubernetes = {
          cluster_init = true;
          disable_kube_proxy = true;
          cluster_cidr = "10.244.0.0/16";
          service_cidr = "10.96.0.0/12";
          tls_san = ["10.0.0.10" "cp-01.internal"];
        };
      };
      checks = import ./checks/ci-control-plane-role.nix {inherit lib;};
    };
    ci-k3s-config = {
      userdata = builtins.toJSON {
        role = "k8s-worker";
        hostname = "worker-labeled";
        kubernetes = {
          server_url = "https://10.0.0.10:6443";
          token_file = "/etc/rancher/k3s/agent-token";
          node_labels = {
            "topology.kubernetes.io/zone" = "us-east-1a";
            "node.kubernetes.io/pool" = "workers";
          };
          registry_mirrors = {
            "docker.io" = "https://mirror.internal/v2";
          };
        };
        firewall = {
          allowed_tcp = [22];
          allowed_udp = [];
          forward_policy = "accept";
        };
      };
      checks = import ./checks/ci-k3s-config.nix {inherit lib;};
    };
    ci-k8s-net-prereqs = {
      userdata = builtins.toJSON {
        role = "k8s-worker";
        hostname = "net-prereqs-test";
        kubernetes = {
          server_url = "https://10.0.0.10:6443";
          token_file = "/etc/rancher/k3s/agent-token";
        };
        firewall = {
          allowed_tcp = [22];
          allowed_udp = [];
          forward_policy = "accept";
        };
      };
      checks = import ./checks/ci-k8s-net-prereqs.nix {inherit lib;};
    };
    ci-service-lifecycle = {
      userdata = builtins.toJSON {
        role = "server";
        hostname = "lifecycle-test";
      };
      checks = import ./checks/ci-service-lifecycle.nix {inherit lib;};
    };
    ci-security = {
      userdata = null;
      checks = import ./checks/ci-security.nix {inherit lib;};
    };
  };

  # Generate VM test derivation for each cloud-init test spec
  ciTests =
    builtins.mapAttrs (
      name: spec:
        harness.mkVMTest {
          inherit name;
          system = goldenSystem;
          checks = [spec.checks];
          userdata = spec.userdata;
        }
    )
    ciCheckSpecs;

  # ---------------------------------------------------------------------------
  # Aggregate helper: trivial derivation that depends on constituent tests
  # ---------------------------------------------------------------------------
  allTests = perCheckTests // ciTests;

  mkAggregate = name: testNames:
    pkgs.mkDerivation {
      pname = "aos-vm-aggregate-${name}";
      version = "0";
      src = null;
      buildDeps = builtins.map (n: allTests.${n}) testNames;
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

    # Cloud-init aggregate targets
    cloud-init = mkAggregate "cloud-init" (builtins.attrNames ciCheckSpecs);
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
  # Collect all check groups for the validation gate
  # ---------------------------------------------------------------------------
  moduleChecks =
    builtins.map (
      name: let
        variantName = checkVariants.${name};
        system = systems.${variantName};
      in
        system.config.system.checks.${name}
    ) (builtins.attrNames checkVariants);

  ciChecks =
    builtins.map (name: ciCheckSpecs.${name}.checks) (builtins.attrNames ciCheckSpecs);

  allChecks = moduleChecks ++ ciChecks;
in
  # Merge: individual tests + cloud-init tests + aggregates/aliases + validate
  allTests
  // aggregates
  // {
    # Pre-flight syntax validation (no VM, instant)
    validate = harness.validateChecks {
      inherit pkgs;
      checks = allChecks;
    };
  }
