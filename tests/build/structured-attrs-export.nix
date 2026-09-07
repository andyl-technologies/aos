# tests/build/structured-attrs-export.nix — Structured derivation environment check
{pkgs}:
pkgs.mkDerivation {
  pname = "aos-structured-attrs-export-check";
  version = "0";
  src = null;

  AOS_STRUCTURED_ATTR_EXPORT_PROBE = "visible-to-child";
  outputChecks = {};
  dontStrip = true;
  dontNukeRefs = true;

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

        mkdir -p "$out"
        echo PASS > "$out/result"
      '';
    }
  ];
}
