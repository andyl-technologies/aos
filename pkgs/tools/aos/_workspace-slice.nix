##! Select a Cargo workspace source from the local dependency graph in Cargo.lock.
{
  lib,
  cargoFlags ? "",
  cargoTestFlags ? "",
  cargoBuildCommands ? [],
}: let
  workspaceRoot = ../../../crates;
  workspaceManifest = builtins.fromTOML (builtins.readFile (workspaceRoot + "/Cargo.toml"));
  lockfile = builtins.fromTOML (builtins.readFile (workspaceRoot + "/Cargo.lock"));

  members = builtins.listToAttrs (
    map
    (path: {
      name = (builtins.fromTOML (builtins.readFile (workspaceRoot + "/${path}/Cargo.toml"))).package.name;
      value = path;
    })
    workspaceManifest.workspace.members
  );
  localPackages = builtins.listToAttrs (
    map
    (package: {
      name = package.name;
      value = package;
    })
    (builtins.filter (package: !(package ? source) && builtins.hasAttr package.name members) lockfile.package)
  );
  dependencyName = dependency: builtins.head (lib.splitString " " dependency);
  packagesIn = command: let
    tokens = builtins.filter (token: token != "") (lib.splitString " " command);
    indices = builtins.genList (index: index) (builtins.length tokens);
    packageAt = index:
      if index + 1 < builtins.length tokens
      then builtins.elemAt tokens (index + 1)
      else throw "Cargo -p flag must name a workspace package";
  in
    map packageAt (builtins.filter (index: builtins.elemAt tokens index == "-p") indices);
  roots = lib.unique (builtins.concatLists (map packagesIn ([cargoFlags cargoTestFlags] ++ cargoBuildCommands)));
  dependenciesOf = name:
    builtins.filter
    (dependency: builtins.hasAttr dependency localPackages)
    (map dependencyName (localPackages.${name}.dependencies or []));

  selectedPackages =
    if roots == [] || !(builtins.all (name: builtins.hasAttr name localPackages) roots)
    then throw "AOS Cargo workspace roots must name packages in Cargo.lock"
    else
      builtins.sort builtins.lessThan (
        map (item: item.key) (builtins.genericClosure {
          startSet = map (key: {inherit key;}) roots;
          operator = item: map (key: {inherit key;}) (dependenciesOf item.key);
        })
      );
  selectedCrates = map (name: members.${name}) selectedPackages;
in {
  src = import ./_workspace-source.nix {
    inherit lib selectedCrates;
  };
  cargoWorkspaceMembers = selectedCrates;
}
