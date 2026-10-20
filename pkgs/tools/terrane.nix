##! terrane — branchable content-addressed store (RFC-0024)
{
  lib,
  stdenv,
  mkCargoPackage,
  aosWorkspaceVendor,
  util-linux,
}: let
  version = "0.1.0";
  # Gates bind the full integration inputs; Cargo providers share upstream's
  # lockfile-only vendor instead of retaining an independent dependency pin.
  src = import ./aos/_workspace-source.nix {
    inherit lib;
    includeIntegrationInputs = true;
  };
  cargoDeps = aosWorkspaceVendor;
  # Linux realizers are target-specific; the portable SDK and CLI are tested
  # on every supported native target (PKG-3).
  testPackages =
    ["terrane-format" "terrane-sdk" "terrane-cli" "aos-terrane-integration"]
    ++ lib.optionals stdenv.hostPlatform.isLinux ["terrane-linux"];
in
  mkCargoPackage {
    platformSupport = {
      build = [
        {
          os = ["linux" "darwin"];
          cpu = ["x86_64" "aarch64"];
        }
      ];
      host = [
        {
          os = ["linux" "darwin"];
          cpu = ["x86_64" "aarch64"];
        }
      ];
      target = [
        {
          os = ["linux" "darwin"];
          cpu = ["x86_64" "aarch64"];
        }
      ];
      role = "public-package";
    };
    pname = "terrane";
    inherit version src cargoDeps;
    cargoRoot = "crates";
    cargoFlags = "-p terrane-cli --bin terrane";
    cargoNextest = true;
    # Keep real-time lease fixtures within the builder's allocated CPU budget.
    cargoNextestMaxTestThreads = 2;
    cargoTestFlags = lib.concatStringsSep " " (map (package: "-p ${package}") testPackages);
    doCheck = true;
    cargoCheckWrapper =
      if stdenv.buildPlatform.isLinux
      then import ./terrane/_protected-check.nix {inherit util-linux;}
      else script: script;
    passthru = {inherit cargoDeps;};
    meta.description = "Branchable content-addressed filesystem store";
  }
