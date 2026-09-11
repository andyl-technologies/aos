##! Packages the fail-closed native adapter matrix evidence adapter.
{pkgs}: {
  name,
  identity,
  matrixSpec,
  matrixCheck,
}: let
  specRoot = pkgs.writeTextFile {
    name = "${name}-spec";
    destination = "/matrix-spec.json";
    text = builtins.toJSON matrixSpec;
  };
  runner = pkgs.writeTextFile {
    name = "${name}-runner";
    destination = "/share/aos-release/qualification-native-adapter-matrix.py";
    text = builtins.readFile ./qualification-native-adapter-matrix.py;
    checkPhase = ''
      PYTHONPYCACHEPREFIX=$TMPDIR/qualification-native-adapter-matrix-pycache \
        ${pkgs.buildPackages.python3}/bin/python3 -m py_compile \
        $out/share/aos-release/qualification-native-adapter-matrix.py
    '';
  };
  executable = pkgs.writeShellScriptBin name ''
    set -euo pipefail

    export AOS_QUALIFICATION_NATIVE_ADAPTER_MATRIX_SPEC=${specRoot}/matrix-spec.json
    export AOS_QUALIFICATION_NATIVE_ADAPTER_MATRIX_CHECK=${builtins.toJSON matrixCheck}

    cat >/dev/null
    PYTHONDONTWRITEBYTECODE=1 \
      ${pkgs.python3}/bin/python3 \
        ${runner}/share/aos-release/qualification-native-adapter-matrix.py

    exec ${pkgs.aos}/bin/aos release qualification respond \
      --request request.json \
      --scenarios scenario-registry.json \
      --report scenario-report.json \
      --identity ${builtins.toJSON identity}
  '';
in
  assert identity != "";
  assert matrixSpec.schema == "aos.qualification.native-adapter-matrix-spec/v1";
  assert matrixSpec.cells != [];
  assert matrixCheck == "native-adapter-matrix-v1-sha256-${builtins.hashString "sha256" (builtins.toJSON matrixSpec)}";
    executable
    // {
      passthru =
        (executable.passthru or {})
        // {
          qualification = {
            inherit identity matrixCheck matrixSpec;
            producesSyntheticSuccess = false;
          };
        };
    }
