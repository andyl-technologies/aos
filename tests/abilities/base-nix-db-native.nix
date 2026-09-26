##! Checks package-store readiness and package-owned runtime integration.
{
  lib,
  pkgs,
}: let
  evaluate = import ./base-module-evaluation.nix {inherit lib pkgs;};
  evaluateStore = selection:
    evaluate ({
        name = "base-nix-db";
        module = {};
        packages = [pkgs.aos-nix-store-provider];
        extraPackageModules = [
          {
            name = "aos";
            version = pkgs.aos.version;
            module = pkgs.aos.module + "/nix-store-database.nix";
          }
        ];
      }
      // selection);
  unselected = evaluateStore {};
  evaluated = evaluateStore {
    enableAbilitySelection = true;
    extraModules = [
      {
        aos.abilities = {
          instances."aos-nix-store-provider:manager".implementation = "aos-nix-store-provider:nix-store-database";
          bindings."test:nix-store-database" = {
            request = "aos:nix-store-database";
            implementation = "aos-nix-store-provider:nix-store-database";
            providerInstance = "aos-nix-store-provider:manager";
            slot = "database";
          };
        };
      }
    ];
  };
  config = evaluated.config;
  requests = config.aos.abilities.requests;
  policyRequests = lib.filterAttrs (_: request: lib.abilities.packageForDeclarationAuthority request.authority == "aos") requests;
  providerRequests = lib.filterAttrs (_: request: lib.abilities.packageForDeclarationAuthority request.authority == "aos-nix-store-provider") requests;
  configurationEntry = providerRequests."aos-nix-store-provider:nix-configuration-entry".parameters;
  configurationSource = configurationEntry.entry.source;
  gcRootMount = providerRequests."aos-nix-store-provider:gcroot-mount".parameters;
  runtimeChecks = config.aos.abilities.runtimeChecks."aos-nix-store-provider:nix-store".checks;
  checkScript = name: (builtins.head (builtins.filter (check: check.name == name) runtimeChecks)).script;
in
  assert lib.filterAttrs (_: request: lib.abilities.packageForDeclarationAuthority request.authority == "aos-nix-store-provider") unselected.config.aos.abilities.requests == {};
  assert unselected.config.aos.abilities.runtimeChecks == {};
  assert builtins.attrNames policyRequests == ["aos:nix-store-database"];
  assert policyRequests."aos:nix-store-database".parameters
  == {
    scope = "local";
    registration = {
      path = "/aos-registration";
      required = false;
    };
    prerequisites = [];
  };
  assert builtins.attrNames providerRequests
  == [
    "aos-nix-store-provider:gcroot-directory"
    "aos-nix-store-provider:gcroot-mount"
    "aos-nix-store-provider:nix-configuration"
    "aos-nix-store-provider:nix-configuration-entry"
    "aos-nix-store-provider:profile-storage"
  ];
  assert providerRequests."aos-nix-store-provider:nix-configuration".parameters.source
  == {
    kind = "inline-text";
    content = ''
      # Managed by the selected AOS package-store provider.
      build-users-group =
    '';
  };
  assert configurationEntry.name == "nix-configuration-entry";
  assert configurationEntry.entry.kind == "copied-file";
  assert configurationEntry.entry.maximum_size_bytes == lib.abilities.types.limits.maxStringLength;
  assert configurationEntry.destination == "/etc/nix/nix.conf";
  assert configurationEntry.owner == "root";
  assert configurationEntry.group == "root";
  assert configurationEntry.mode == "0444";
  assert configurationSource.kind == "execution-path";
  assert configurationSource.resource.request == "aos-nix-store-provider:nix-configuration";
  assert configurationSource.resource.output == "resource";
  assert configurationSource.path.request == "aos-nix-store-provider:nix-configuration";
  assert configurationSource.path.output == "planned-path";
  assert builtins.head configurationEntry.prerequisites == configurationSource.resource;
  assert providerRequests."aos-nix-store-provider:profile-storage".parameters.requested_path == "/var/lib/profiles";
  assert providerRequests."aos-nix-store-provider:gcroot-directory".parameters.destination
  == "/nix/var/nix/gcroots/aos-profiles";
  assert gcRootMount.name == "aos-profile-gcroots";
  assert gcRootMount.enabled;
  assert gcRootMount.options == ["bind"];
  assert gcRootMount.source.request == "aos-nix-store-provider:profile-storage";
  assert gcRootMount.source.output == "planned-path";
  assert gcRootMount.destination.request == "aos-nix-store-provider:gcroot-directory";
  assert gcRootMount.destination.output == "planned-path";
  assert config.environment.etc == {};
  assert (lib.abilities.types.schemaOf "runtime checks" evaluated.options.aos.abilities.runtimeChecks.type).kind == "map";
  assert builtins.attrNames config.aos.abilities.runtimeChecks == ["aos-nix-store-provider:nix-store"];
  assert builtins.map (check: check.name) runtimeChecks
  == [
    "database-ready"
    "managed-config"
    "gcroot-bridge"
    "current-system-valid"
  ];
  assert lib.hasInfix "${pkgs.coreutils}/bin/test" (checkScript "database-ready");
  assert lib.hasInfix "${pkgs.grep}/bin/grep" (checkScript "managed-config");
  assert lib.hasInfix "${pkgs.coreutils}/bin/stat" (checkScript "gcroot-bridge");
  assert lib.hasInfix "${pkgs.nix}/bin/nix-store" (checkScript "current-system-valid");
  assert lib.hasInfix "${pkgs.coreutils}/bin/readlink" (checkScript "current-system-valid");
  assert (config.systemd.services or {}) == {}; true
