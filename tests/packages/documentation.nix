##! Checks declaration-derived package documentation and public library imports.
{lib, pkgs, ...}: let
  nativeChecks = (import ../effects/packages.nix).checks;
  serviceChecks = import ../effects/service-management.nix;
  documentedPackages = {
    service-management = pkgs.service-management;
    systemd = pkgs.systemd;
    dbus = pkgs.dbus;
  };
  validDocumentation = name: package: let
    document = package.documentation;
    encoded = builtins.toJSON document;
  in
    document.schema == "aos.module.documentation"
    && document.scope == ["package" name]
    && document.options != []
    && builtins.any (entry: entry.name == name) document.packages
    && !(package ? abilities)
    && !lib.hasInfix "\"_type\"" encoded;

  discoverNixSources = directory: prefix:
    lib.concatMap (
      name: let
        entryType = (builtins.readDir directory).${name};
        relative = "${prefix}${name}";
      in
        if entryType == "directory"
        then discoverNixSources (directory + "/${name}") "${relative}/"
        else
          lib.optional (
            entryType
            == "regular"
            && builtins.match ".*\\.nix" name != null
            && relative != "default.nix"
          ) {
            inherit relative;
            source = directory + "/${name}";
          }
    ) (builtins.attrNames (builtins.readDir directory));
  packageSources = discoverNixSources ../../pkgs "";
  importsPrivateLibrary = source:
    builtins.any (
      line:
        builtins.match ".*import[[:space:]]+(\\.\\./)+lib/.*" line
        != null
        || builtins.match ".*import[[:space:]]+\\((\\.\\./)+lib/.*" line != null
    ) (lib.splitString "\n" (builtins.readFile source));
  privateLibraryImports =
    builtins.map
    (entry: entry.relative)
    (builtins.filter (entry: importsPrivateLibrary entry.source) packageSources);

in
  assert builtins.all (value: value) (builtins.attrValues nativeChecks);
  assert builtins.all (value: value) (builtins.attrValues serviceChecks);
  assert builtins.all (name: validDocumentation name documentedPackages.${name})
    (builtins.attrNames documentedPackages);
  if privateLibraryImports != []
  then throw "package definitions import private library paths: ${builtins.concatStringsSep ", " privateLibraryImports}"
  else pkgs.mkDerivation {
    pname = "package-documentation-policy-check";
    version = "0";
    src = null;
    outputChecks = {};
    phases = [{
      name = "check";
      script = ''
        mkdir -p "$out"
        printf 'PASS\n' > "$out/result"
      '';
    }];
  }
