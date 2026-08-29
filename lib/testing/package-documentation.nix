##! lib/testing/package-documentation.nix — RFC-0015 documentation policy gate.
{
  lib,
  pkgs,
}: let
  allowedConceptualGuides = [
    "README.md"
    "cli.md"
    "configuration.md"
    "deployment.md"
    "host-nix.md"
    "installation.md"
    "networking.md"
    "operations.md"
    "package-authoring.md"
    "packages.md"
    "quickstart.md"
    "recovery.md"
    "secrets.md"
    "security.md"
    "support-status.md"
    "troubleshooting.md"
    "upgrades.md"
  ];
  observedGuides = lib.sort builtins.lessThan (lib.filter
    (name: lib.hasSuffix ".md" name)
    (builtins.attrNames (builtins.readDir ../../docs/users/aos)));
  configurablePackages = [
    pkgs.aos-registry-server
    pkgs.cilium
    pkgs.cloudcore
    pkgs.conntrack-tools
    pkgs.containerd
    pkgs.edgecore
    pkgs.envoy
    pkgs.etcd
    pkgs.garage
    pkgs.k3s-combined
    pkgs.k3s-control-plane
    pkgs.k3s-worker
    pkgs.krb5
    pkgs.longhorn-manager
    pkgs.mariadb
    pkgs.nginx
    pkgs.openldap
    pkgs.postgresql
    pkgs.rsync
  ];
in
  if observedGuides != allowedConceptualGuides
  then
    throw ''
      docs/users/aos may contain only the reviewed conceptual guides. Package
      option/runtime reference belongs in configModule.documentation so every
      authenticated documentation surface is generated from one Nix authority.
    ''
  else
    pkgs.mkDerivation {
      pname = "package-documentation-policy-check";
      version = "0";
      src = null;
      buildDeps = [pkgs.jq] ++ map (package: package.config) configurablePackages;
      phases = [
        {
          name = "check";
          script = ''
            for metadata in \
              ${lib.concatMapStringsSep " " (package: "${package.config}/config-meta.json") configurablePackages}
            do
              jq -e '
                (.documentation.summary | type == "string" and length > 0)
                and (.documentation.sections | type == "object" and length > 0)
              ' "$metadata" >/dev/null
            done

            mkdir -p "$out"
            printf 'PASS\n' > "$out/result"
          '';
        }
      ];
    }
