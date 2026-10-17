# Genuine packaged Main and external-client controls in the existing kernel VM.
{
  pkgs,
  lib,
  mkSystem,
  attrPath,
}: let
  nativeQemu = pkgs.qemu-crucible;
  nativePlugin = pkgs.crucible-qemu-plugin;
  guest = import ./phase2-qemu-live-plugin-quantum-guest.nix {inherit pkgs;};
  rootImage = import ./_ram-native-root-image.nix {inherit pkgs;};
  inputs = import ./_ram-normal-service-inputs.nix {
    inherit pkgs lib nativeQemu nativePlugin guest rootImage;
  };
  quotaInstaller = import ./_catalog-quota-installer.nix {inherit pkgs lib;};
  deployment = import ./_ram-normal-service-deployment.nix {inherit pkgs lib;};
  installedInputs = "/var/lib/crucible-campaign/normal-inputs";
  store = builtins.toFile "normal-ram-semantic-store.toml" ''
    schema = "crucible.campaign-repository-store"
    version = 3
    root = "semantic"
    admitted_kinds = ["campaign-fact", "campaign-snapshot", "merkle-node", "scenario", "configuration", "policy", "exact-manifest", "ram-extent", "disk-extent", "device-state", "observation", "finding", "projection", "trace"]
    ref_directory = "/var/paging-storage/semantic/refs"
    [[nodes]]
    id = "semantic"
    [nodes.spec]
    kind = "directory"
    root = "/var/paging-storage/semantic/objects"
  '';
  serviceModule = ./_ram-normal-service-module.nix;
  fixtureInputs = {inherit inputs deployment store nativeQemu nativePlugin guest rootImage;};
  preparation = ''
    ${pkgs.coreutils}/bin/mkdir -m 700 -p \
      ${installedInputs} /var/paging-storage/semantic \
      /var/paging-storage/run /var/paging-storage/lifecycle
    ${pkgs.coreutils}/bin/cp -R ${inputs}/state/. /var/paging-storage/semantic/
    ${pkgs.coreutils}/bin/chmod -R u+rwX,go-rwx /var/paging-storage/semantic
    for input in component-authority.bin ca.pem server.pem server.key client.pem client.key; do
      ${pkgs.coreutils}/bin/cp ${inputs}/"$input" ${installedInputs}/"$input"
      ${pkgs.coreutils}/bin/chmod 600 ${installedInputs}/"$input"
    done
    ${quotaInstaller}/bin/install-catalog-quota \
      /var/paging-storage /var/paging-storage/ram-catalogs 36000 536870912 262144
    ${quotaInstaller}/bin/install-catalog-quota \
      /var/paging-storage /var/paging-storage/executor-ledger 36001 16777216 65536
  '';
in
  import ./ram-normal-service.nix {
    inherit pkgs lib mkSystem attrPath serviceModule fixtureInputs nativeQemu nativePlugin preparation;
    campaign = "normal-ram";
    attemptFile = "${inputs}/attempt-id";
    clientAuthorityFile = "${installedInputs}/ca.pem";
    clientCertificateFile = "${installedInputs}/client.pem";
    clientKeyFile = "${installedInputs}/client.key";
    idempotencyKey = builtins.concatStringsSep "" (builtins.genList (_: "63") 32);
    inputDependencies = [inputs deployment store quotaInstaller];
  }
