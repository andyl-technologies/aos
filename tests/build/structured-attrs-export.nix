# tests/build/structured-attrs-export.nix — Structured derivation environment check
{pkgs}: let
  firstRuntimeInput = pkgs.mkDerivation {
    pname = "aos-structured-attrs-first-runtime-input";
    version = "0";
    src = null;
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out"
          echo first > "$out/value"
        '';
      }
    ];
  };
  secondRuntimeInput = pkgs.mkDerivation {
    pname = "aos-structured-attrs-second-runtime-input";
    version = "0";
    src = null;
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out"
          echo second > "$out/value"
        '';
      }
    ];
  };
  scrubProbe = pkgs.mkDerivation {
    pname = "aos-structured-attrs-scrub-probe";
    version = "0";
    src = null;
    runtimeDeps = [firstRuntimeInput secondRuntimeInput];
    dontStrip = true;
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"
          cat > "$out/bin/runtime-paths" <<'EOF'
          ${firstRuntimeInput}
          ${secondRuntimeInput}
          EOF
        '';
      }
    ];
  };
in
  pkgs.mkDerivation {
    pname = "aos-structured-attrs-export-check";
    version = "0";
    src = null;

    AOS_STRUCTURED_ATTR_EXPORT_PROBE = "visible-to-child";
    outputChecks = {};
    dontStrip = true;
    dontNukeRefs = true;
    buildDeps = [scrubProbe];

    phases = [
      {
        name = "check";
        script = ''
          child_value=$(
            ${pkgs.bash}/bin/bash -c \
              'printf "%s" "$AOS_STRUCTURED_ATTR_EXPORT_PROBE"'
          )
          if [ "$child_value" != "$AOS_STRUCTURED_ATTR_EXPORT_PROBE" ]; then
            echo "structured derivation attrs were not exported to a child process" >&2
            exit 1
          fi

          grep -Fqx '${firstRuntimeInput}' ${scrubProbe}/bin/runtime-paths
          grep -Fqx '${secondRuntimeInput}' ${scrubProbe}/bin/runtime-paths

          mkdir -p "$out"
          echo PASS > "$out/result"
        '';
      }
    ];
  }
