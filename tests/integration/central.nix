# tests/integration/central.nix — Cross-cutting and ABI integration tests
#
# Tests that exercise multi-package interactions or system-wide properties.
# These cannot be attributed to a single package, so they live here rather
# than as `checks` on individual package derivations.
#
# Usage:
#   nix-build -A checks.integration.cross-cutting-tls-stack
#   nix-build -A checks.integration.abi-soname-validation

{ pkgs, testing }:

let
  crossCutting = import ./cross-cutting.nix { inherit pkgs testing; };
  abiChecks = import ./abi-checks.nix { inherit pkgs testing; };

  prefixAttrs =
    prefix: attrs:
    builtins.listToAttrs (
      builtins.map (name: {
        name = "${prefix}-${name}";
        value = attrs.${name};
      }) (builtins.attrNames attrs)
    );

  # Only keep truly multi-package cross-cutting tests.
  # Tests that primarily exercise a single package are moved to that package's
  # `checks` attribute instead.
  centralCrossCutting = builtins.intersectAttrs {
    tls-stack = true;
    c-pipeline = true;
    compression-interop = true;
    archive-chain = true;
    pkg-config-chain = true;
    multi-lib-link = true;
    network-firewall-stack = true;
    tls-full-chain = true;
    config-validity = true;
  } crossCutting;
in
prefixAttrs "cross-cutting" centralCrossCutting // prefixAttrs "abi" abiChecks
