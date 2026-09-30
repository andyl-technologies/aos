##! Native authoring and package behavior checks, grouped for existing check targets.
{
  pkgs,
  lib,
}: let
  # Every fixture leaf is a checked boolean. Forcing an attribute set alone
  # would allow a false policy check to silently produce a passing derivation.
  verify = path: value:
    if builtins.isAttrs value
    then builtins.all (name: verify (path ++ [name]) value.${name}) (builtins.attrNames value)
    else if builtins.isList value
    then builtins.all (item: verify path item) value
    else if value == true
    then true
    else throw "native check failed: ${builtins.concatStringsSep "." path}";

  fixture = path: let
    imported =
      if path == ../effects/packages.nix
      then (import path).checks
      else import path;
    arguments = {inherit pkgs lib;};
  in
    if builtins.isFunction imported
    then imported (builtins.intersectAttrs (builtins.functionArgs imported) arguments)
    else imported;

  suite = name: paths:
    assert builtins.all (path: verify [name (builtins.baseNameOf path)] (fixture path)) paths;
      pkgs.mkDerivation {
        pname = "aos-native-${name}-checks";
        version = "0";
        src = null;
        phases = [
          {
            name = "check";
            script = ''
              mkdir -p "$out"
              echo PASS > "$out/result"
            '';
          }
        ];
      };
in {
  # These fixtures retain only tiny authored package sources and inert payload
  # identities, keeping core authoring independent of the system package graph.
  authoring = suite "authoring" [
    ../effects/modules.nix
    ../effects/types.nix
    ../effects/composition.nix
    ../effects/frozen-handler.nix
    ../effects/stages.nix
    ../effects/packages.nix
    ./domain-selection.nix
    ../effects/provenance-projection.nix
  ];

  package-services = suite "package-services" [
    ../effects/daemon-consumers.nix
    ../effects/database-consumers.nix
    ../effects/runtime-checks.nix
    ../effects/reference-nginx.nix
    ../effects/hub-consumer.nix
    ../effects/release-maintenance.nix
    ./configuration-evaluation-service.nix
    ./service-features.nix
    ./systemd-service-realization.nix
    ./dbus-service.nix
    ./k3s-controller-terminal.nix
    ./docker-service.nix
    ./tailscale-service.nix
    ./nginx-service.nix
    ./krb5-kdc-service.nix
    ./libvirt-service.nix
    ./bind-service.nix
    ./postgresql-service.nix
    ./mariadb-service.nix
    ./smartmontools-service.nix
    ./kubernetes-package-services.nix
    ./zfstools-service.nix
  ];

  provider-realization = suite "provider-realization" [
    ../effects/systemd-resources.nix
    ./util-linux-getty.nix
    ./filesystem-entry-provider.nix
  ];

  native-resources = suite "native-resources" [
    ../effects/configuration-lower.nix
    ../effects/boot-consumers.nix
    ../effects/security-services.nix
    ./block-storage.nix
    ./base-filesystems-native.nix
    ./initrd-security-services.nix
    ../effects/measured-var.nix
    ../effects/image-retirement.nix
  ];

  system-selection = suite "system-selection" [
    ../effects/security-policy.nix
    ../effects/platform-replay.nix
    ./containerd-static-projection.nix
  ];

  system-packages = suite "system-packages" [
    ../effects/release-native-inventory.nix
    ./package-option-provenance.nix
    ./package-qualification.nix
  ];
}
