##! Explicit realized artifacts shared by package builds and deployment evaluation.
{}: let
  nameFor = package: package.catalogName or package.pname or package.name;
  reference = package: {
    name = nameFor package;
    version = package.version or "0";
    path = builtins.toString package;
    outputs = builtins.listToAttrs (builtins.map (output: {
      name = output;
      value = builtins.toString (package.${output} or package);
    }) (package.outputs or ["out"]));
    mainProgram = package.meta.mainProgram or package.pname or null;
  };
  # Every output of a derivation carries the same deployment envelope. Module
  # identity follows that envelope; selected payload outputs remain explicit.
  canonicalReference = package: package.deployment.package or (reference package);
  canonicalDependencies = package: package.deployment.runtimeDependencies or (keyed (package.runtimeDeps or []));
  keyed = packages:
    builtins.foldl' (result: package: let
      name = nameFor package;
      value = reference package;
    in
      if result ? ${name} && result.${name} != value
      then throw "Package dependency '${name}' resolves to conflicting artifacts."
      else result // {${name} = value;}) {}
    packages;
  unique = references:
    builtins.attrValues (builtins.foldl' (result: artifact: let
      path = builtins.unsafeDiscardStringContext artifact.path;
    in
      if result ? ${path} && result.${path} != artifact
      then throw "Artifact '${path}' has conflicting package identities."
      else result // {${path} = artifact;}) {}
    references);
  moduleReference = package: {
    name = nameFor package;
    version = package.version or "0";
    source = builtins.toString package.module;
    entrypoint = "module.nix";
  };
  envelope = package: {
    schema = "aos.package.deployment";
    system = package.targetSystem or package.system;
    package = reference package;
    module =
      if package ? module
      then moduleReference package
      else null;
    runtimeDependencies = keyed (package.runtimeDeps or []);
    moduleDependencies = builtins.map moduleReference (package.moduleDeps or []);
  };
  valid = reference:
    builtins.isAttrs reference
    && builtins.attrNames reference == ["mainProgram" "name" "outputs" "path" "version"]
    && builtins.isString reference.name
    && builtins.isString reference.version
    && builtins.isString reference.path
    && builtins.match "/nix/store/[^/]+" reference.path != null
    && (reference.mainProgram == null || (builtins.isString reference.mainProgram && !builtins.elem reference.mainProgram ["." ".."] && builtins.match "[A-Za-z0-9+._-]+" reference.mainProgram != null))
    && builtins.isAttrs reference.outputs
    && builtins.elem reference.path (builtins.attrValues reference.outputs)
    && builtins.all (path: builtins.isString path && builtins.match "/nix/store/[^/]+" path != null) (builtins.attrValues reference.outputs);
  # These are artifact values, deliberately not pretend derivations. Their
  # string coercion permits ordinary interpolation in module configuration.
  value = reference: let
    base = selected:
      reference
      // {
        _type = "aos-package-artifact";
        path = selected;
        outPath = selected;
        __toString = _: selected;
        meta =
          if reference.mainProgram == null
          then {}
          else {inherit (reference) mainProgram;};
      };
    outputs = builtins.mapAttrs (_: path: base path // outputs) reference.outputs;
  in
    base reference.path // outputs;
in {inherit nameFor reference canonicalReference canonicalDependencies keyed unique moduleReference envelope value valid;}
