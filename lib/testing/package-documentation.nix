##! lib/testing/package-documentation.nix — RFC-0015 documentation policy gate.
{
  lib,
  pkgs,
  system,
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
  serviceCatalog = import ../service-documentation.nix;
  serviceNames = builtins.attrNames serviceCatalog.services;
  packageServiceNames =
    builtins.filter
    (name: serviceCatalog.services.${name}.ownership == "package")
    serviceNames;
  configurablePackages =
    builtins.map
    (name:
      pkgs.${name}
      or (throw "service documentation catalog references missing package '${name}'"))
    packageServiceNames;
  optionSurface = lib.optionSurface system;
  prefixMatches = prefix: option:
    option.pathStr == prefix || lib.hasPrefix "${prefix}." option.pathStr;
  systemServiceNames =
    builtins.filter
    (name: builtins.elem serviceCatalog.services.${name}.ownership ["platform" "system"])
    serviceNames;
  undocumentedSystemServices =
    builtins.filter (
      name: let
        service = serviceCatalog.services.${name};
        selected =
          builtins.filter
          (option:
            option.visibility
            != "internal"
            && (service.ownership
              == "platform"
              || builtins.any (prefix: prefixMatches prefix option) service.optionPrefixes))
          optionSurface;
      in
        selected
        == []
        || builtins.any (option: option.description == "") selected
        || (service.units or []) == []
    )
    systemServiceNames;
in
  if observedGuides != allowedConceptualGuides
  then
    throw ''
      docs/users/aos may contain only the reviewed conceptual guides. Package
      option/runtime reference belongs in configModule.documentation so every
      authenticated documentation surface is generated from one Nix authority.
    ''
  else if serviceCatalog.schema != "aos.service-documentation/v1"
  then throw "unsupported service documentation catalog schema"
  else if undocumentedSystemServices != []
  then throw "system service documentation is missing typed options, descriptions, or units: ${builtins.concatStringsSep ", " undocumentedSystemServices}"
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
