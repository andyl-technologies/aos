##! Builds one immutable declarative package qualification probe.
{
  pkgs,
  lib,
}: {
  name,
  spec,
}: let
  expectedMembers = ["bad_input" "package" "primary" "schema_version"];
  operationMembers = ["artifacts" "expected" "files" "input" "operation" "steps"];
  validOperation = operation:
    builtins.isAttrs operation
    && builtins.attrNames operation == operationMembers
    && builtins.all (member: builtins.hasAttr member operation) operationMembers
    && builtins.isAttrs operation.files
    && builtins.isList operation.steps
    && operation.steps != []
    && builtins.isList operation.artifacts;
  specification = pkgs.writeTextFile {
    name = "${name}-specification";
    destination = "/specification.json";
    text = builtins.toJSON spec;
  };
  runner = pkgs.writeTextFile {
    name = "qualification-package-probe-runner";
    destination = "/share/aos-release/qualification-package-probe.py";
    text = builtins.readFile ./qualification-package-probe.py;
    checkPhase = ''
      PYTHONPYCACHEPREFIX=$TMPDIR/qualification-package-probe-pycache \
        ${pkgs.buildPackages.python3}/bin/python3 -m py_compile \
        $out/share/aos-release/qualification-package-probe.py
    '';
  };
  probe = pkgs.writeShellScriptBin "qualification-package-${name}-probe" ''
    exec "$AOS_QUALIFICATION_PYTHON" \
      ${lib.escapeShellArg "${runner}/share/aos-release/qualification-package-probe.py"} \
      ${lib.escapeShellArg "${specification}/specification.json"}
  '';
in
  assert name != "";
  assert builtins.attrNames spec == expectedMembers;
  assert spec.schema_version == "aos.release.package-probe/v1";
  assert spec.package == name;
  assert validOperation spec.primary;
  assert validOperation spec.bad_input;
    lib.getExe probe
