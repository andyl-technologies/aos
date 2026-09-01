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
  managedPackageNames = lib.sort builtins.lessThan (lib.unique (
    builtins.filter
    (name: let
      value = builtins.tryEval pkgs.${name};
    in
      value.success
      && builtins.isAttrs value.value
      && (value.value ? config || value.value ? expose))
    (builtins.attrNames pkgs)
  ));
  unmanagedUnitPackages =
    builtins.filter
    (name: let
      value = builtins.tryEval pkgs.${name};
    in
      value.success
      && builtins.isAttrs value.value
      && value.value ? systemdUnitInventory
      && !(value.value ? expose))
    (builtins.attrNames pkgs);
  catalogedManagedNames = lib.sort builtins.lessThan (packageServiceNames ++ serviceCatalog.fixtures);
  unmanagedPackages = builtins.filter (name: !builtins.elem name catalogedManagedNames) managedPackageNames;
  staleCatalogPackages = builtins.filter (name: !builtins.elem name managedPackageNames) catalogedManagedNames;
  invalidNonServices = builtins.filter (name: let
    value = pkgs.${name} or null;
  in
    value
    == null
    || !builtins.isString serviceCatalog.nonServices.${name}
    || serviceCatalog.nonServices.${name} == ""
    || value ? config
    || value ? expose) (builtins.attrNames serviceCatalog.nonServices);
  configurablePackages =
    builtins.map
    (name:
      pkgs.${name}
      or (throw "service documentation catalog references missing package '${name}'"))
    packageServiceNames;
  baseLib = system.config.aos.config.evalAtBoot.baseLib;
  auditPackageOptions = name: let
    package = pkgs.${name};
    dependencyOutputs = lib.concatStringsSep " " (lib.mapAttrsToList
      (dependencyName: _: "${builtins.toJSON dependencyName} = builtins.toString <aos-documentation-audit-dependency-${dependencyName}>;")
      (package.configModuleDependencies or {}));
    dependencySearchPaths = lib.concatStringsSep " " (lib.mapAttrsToList
      (dependencyName: output: "-I aos-documentation-audit-dependency-${dependencyName}=${output}")
      (package.configModuleDependencies or {}));
    expression = ''
      let
        base = import <aos-documentation-audit-base-lib>;
        configRoot = <aos-documentation-audit-config>;
        metadata = builtins.fromJSON (builtins.readFile <aos-documentation-audit-config/config-meta.json>);
        authorization = {
          owns = builtins.map (owned: owned.root) metadata.owns_roots;
          contributes = builtins.listToAttrs (builtins.map
            (contribution: {
              name = contribution.root;
              value = contribution.paths;
            })
            metadata.contributes);
        };
        evaluated = base.lib.evalModules {
          modules = [];
          packageModules = [{
            name = ${builtins.toJSON name};
            inherit authorization configRoot;
            module = <aos-documentation-audit-config/module.nix>;
            outputs = {
              self = builtins.toString <aos-documentation-audit-runtime>;
              dependencies = { ${dependencyOutputs} };
            };
          }];
          inherit (base) lib;
        };
        optionSurface = base.lib.optionSurface evaluated;
        publicOptions = builtins.filter
          (option: option.visibility != "internal")
          optionSurface;
        declaredOptions = builtins.sort builtins.lessThan metadata.declares;
        evaluatedOptions = builtins.sort builtins.lessThan (builtins.map
          (option: option.pathStr)
          (builtins.filter
            (option: !(builtins.match "_module(\\..*)?" option.pathStr != null))
            optionSurface));
        authoredContributable = builtins.sort builtins.lessThan (builtins.concatMap
          (owned: builtins.map (path: "''${owned.root}.''${path}") owned.contributable)
          metadata.owns_roots);
        evaluatedContributable = builtins.sort builtins.lessThan (builtins.map
          (option: option.pathStr)
          (builtins.filter (option: option.contributable) optionSurface));
        undocumented = builtins.map
          (option: option.pathStr)
          (builtins.filter (option: option.description == "") publicOptions);
      in
        if publicOptions == [] then
          throw "package '${name}' has no public configuration options"
        else if undocumented != [] then
          throw "package '${name}' has undocumented public configuration options: ''${builtins.concatStringsSep ", " undocumented}"
        else if declaredOptions != evaluatedOptions then
          throw "package '${name}' declaration claims do not exactly match its evaluated options: declared=''${builtins.toJSON declaredOptions}, evaluated=''${builtins.toJSON evaluatedOptions}"
        else if authoredContributable != evaluatedContributable then
          throw "package '${name}' contributable claims do not exactly match its evaluated option surface: authored=''${builtins.toJSON authoredContributable}, evaluated=''${builtins.toJSON evaluatedContributable}"
        else
          ${builtins.toJSON name}
    '';
  in ''
    NIX_PATH= \
    NIX_PROFILES= \
    NIX_STATE_DIR="$TMPDIR/nix-state" \
    NIX_LOG_DIR="$TMPDIR/nix-log" \
    NIX_CONF_DIR="$TMPDIR/nix-conf" \
    NIX_USER_PROFILE_DIR="$TMPDIR/nix-profiles" \
    ${pkgs.nix}/bin/nix-instantiate \
      --store dummy:// \
      --eval \
      --strict \
      --json \
      --option restrict-eval true \
      --option allow-import-from-derivation false \
      -I aos-documentation-audit-base-lib=${baseLib} \
      -I aos-documentation-audit-config=${package.config} \
      -I aos-documentation-audit-runtime=${package} \
      ${dependencySearchPaths} \
      --expr ${lib.escapeShellArg expression} >/dev/null
  '';
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
  else if unmanagedPackages != [] || staleCatalogPackages != []
  then throw "managed package service inventory drift (unmanaged: ${builtins.concatStringsSep ", " unmanagedPackages}; stale: ${builtins.concatStringsSep ", " staleCatalogPackages})"
  else if unmanagedUnitPackages != []
  then throw "packages shipping systemd units must expose a typed service contract: ${builtins.concatStringsSep ", " unmanagedUnitPackages}"
  else if invalidNonServices != []
  then throw "on-demand package dispositions are missing, stale, or unexpectedly managed: ${builtins.concatStringsSep ", " invalidNonServices}"
  else if undocumentedSystemServices != []
  then throw "system service documentation is missing typed options, descriptions, or units: ${builtins.concatStringsSep ", " undocumentedSystemServices}"
  else
    pkgs.mkDerivation {
      pname = "package-documentation-policy-check";
      version = "0";
      src = null;
      buildDeps =
        [pkgs.jq pkgs.nix baseLib]
        ++ configurablePackages
        ++ map (package: package.config) configurablePackages;
      outputChecks = {};
      exportReferencesGraph.servicePackages = configurablePackages;
      phases = [
        {
          name = "check";
          script = ''
            # Restricted documentation evaluations use only the explicit
            # authenticated -I bindings below. An empty NIX_PATH also keeps
            # Nix from probing the daemon's global profile hierarchy inside
            # the sandbox.
            mkdir -p \
              "$TMPDIR/nix-state" \
              "$TMPDIR/nix-log" \
              "$TMPDIR/nix-conf" \
              "$TMPDIR/nix-profiles"

            ${lib.concatMapStringsSep "\n" (package: ''
                jq -e --arg description ${lib.escapeShellArg package.meta.description} '
                  (.documentation.summary == $description)
                  and (.documentation.sections | type == "object" and length > 0)
                  and ([
                    .documentation.sections[]
                    | ..
                    | objects
                    | select(.kind? == "note")
                    | (.blocks | type == "array")
                  ] | all)
                ' ${package.config}/config-meta.json >/dev/null
              '')
              configurablePackages}

            ${lib.concatMapStringsSep "\n" (package:
              lib.concatMapStringsSep "\n" (dependency: ''
                jq -e \
                  --arg package ${lib.escapeShellArg (builtins.toString package)} \
                  --arg dependency ${lib.escapeShellArg (builtins.toString dependency)} \
                  '.servicePackages
                    | map(select(.path == $package))
                    | length == 1
                      and (.[0].references | index($dependency) != null)' \
                  "$NIX_ATTRS_JSON_FILE" >/dev/null
              '') (builtins.attrValues (package.configModuleDependencies or {})))
            configurablePackages}

            ${lib.concatMapStringsSep "\n" auditPackageOptions packageServiceNames}

            mkdir -p "$out"
            printf 'PASS\n' > "$out/result"
          '';
        }
      ];
    }
