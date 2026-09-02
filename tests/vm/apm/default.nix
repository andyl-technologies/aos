# tests/vm/apm/default.nix — APM/APR VM test suite
#
# Exposes all registry, tracking, package management, system update,
# kernel upgrade, image download, binary cache,
# multi-registry, ConnectRPC, and end-to-end lifecycle tests as a flat
# attribute set of derivations.  Each test is a headless Firecracker microVM
# derivation that exits 0 on PASS.
#
# Usage:
#   nix-build -A checks.vm.apm.registry-create
#   nix-build -A checks.vm.apm.tracking-branch
#   nix-build -A checks.vm.apm.install-basic
#   nix-build -A checks.vm.apm.command-surface
# Sysroot-lock acceptance uses the authenticated production image state:
#   nix-build -A checks.fleet.apm-sysroot-lock
#   nix-build -A checks.vm.apm.system-install
#   nix-build -A checks.vm.apm.system-transition-options
#   nix-build -A checks.vm.apm.image-pull-raw
#   nix-build -A checks.vm.apm.cache-push-pull
#   nix-build -A checks.vm.apm.rpc-cache-query-missing
#   nix-build -A checks.vm.apm.e2e-full-lifecycle
#   nix-build -A checks.vm.apm.registry-validation-stock-nix-backend-array
{
  testing,
  pkgs,
}: let
  # These interaction tests need both public package surfaces. Keep their
  # convenience layout local to the test suite; production outputs stay
  # disjoint and never install compatibility aliases.
  aosPkg = pkgs.mkDerivation {
    pname = "aos-apm-apr-vm-test-suite";
    version = pkgs.aos.version;
    src = null;
    runtimeDeps = [pkgs.aos.apm pkgs.aos.apr];
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"
          ln -s ${pkgs.aos.apm}/bin/apm "$out/bin/apm"
          ln -s ${pkgs.aos.apr}/bin/apr "$out/bin/apr"
        '';
      }
    ];
  };

  registryTests = import ./registry.nix {inherit testing pkgs aosPkg;};
  registryValidationTests = import ./registry_validation.nix {inherit testing pkgs aosPkg;};
  trackingTests = import ./tracking.nix {inherit testing pkgs aosPkg;};
  packageTests = import ./packages.nix {inherit testing pkgs aosPkg;};
  systemTests = import ./system.nix {
    inherit testing pkgs;
    apm = aosPkg;
  };
  kernelTests = import ./kernel.nix {
    inherit testing pkgs;
    apm = aosPkg;
  };
  imageTests = import ./image.nix {
    inherit testing pkgs;
    apm = aosPkg;
  };

  # Binary cache, multi-registry, ConnectRPC, and end-to-end tests
  cacheTests = import ./cache.nix {
    inherit testing pkgs;
    self = aosPkg;
  };
  multiRegistryTests = import ./multi_registry.nix {
    inherit testing pkgs;
    self = aosPkg;
  };
  rpcTests = import ./rpc.nix {
    inherit testing pkgs;
    self = aosPkg;
  };
  e2eTests = import ./e2e.nix {
    inherit testing pkgs;
    self = aosPkg;
  };
  trustAnchorTests = import ./trust_anchor.nix {inherit testing pkgs aosPkg;};
in
  registryTests
  // registryValidationTests
  // trackingTests
  // packageTests
  // systemTests
  // kernelTests
  // imageTests
  // cacheTests
  // multiRegistryTests
  // rpcTests
  // e2eTests
  // trustAnchorTests
